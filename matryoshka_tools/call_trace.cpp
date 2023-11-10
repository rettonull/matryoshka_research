#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <cstdlib>
#include <map>
#include <vector>
#include <set>

// Command line options
KNOB<BOOL> opt_canonical(KNOB_MODE_WRITEONCE, "pintool", "c", "0", "Use canonical names -- MTRYKA_1, etc.");
KNOB<std::string> opt_detailedcalls(KNOB_MODE_WRITEONCE, "pintool", "d", "", "Calls to log in detail");
KNOB<std::string> opt_searchaddrs(KNOB_MODE_WRITEONCE, "pintool", "a", "", "Addresses to find calls for");
KNOB<std::string> opt_logfile(KNOB_MODE_WRITEONCE, "pintool", "o", "log.txt", "Output log file");

std::ofstream logfile;
bool canonical = false;

// Globals
std::map<ADDRINT, std::string> api_map;
std::vector<ADDRINT> call_stack;
std::set<ADDRINT> detailed_calls, search_addrs;

// Execution environment information
constexpr ADDRINT IDA_BASE = 0x140001000;
ADDRINT text_base = 0, text_end = 0,
        func_start = 0x140001000, func_ret = 0x140002E07;

OS_THREAD_ID main_thread = 0;
bool loading_done = false, search_mode = false;

// Convert an IDA-based address to a real memory address
ADDRINT IDA_to_realaddr(ADDRINT IDA_addr)
{
    return IDA_addr - IDA_BASE + text_base;
}

// Convert a real memory address to an IDA-based address
ADDRINT realaddr_to_IDA(ADDRINT real_addr)
{
    return real_addr - text_base + IDA_BASE;
}

// Log line indentation for nested calls
void indent()
{
    size_t indent_level = call_stack.size();

    if (indent_level)
        for (size_t i = 0; i < indent_level - 1; i++)
            logfile << '\t';
}

// Write spacing between end of instruction disassemblies
// and beginning of registry values
VOID pad_ins(size_t disasm_size)
{
    for (size_t i = 0; i < 40 - disasm_size; i++)
        logfile << ' ';
}

// Safely read memory value up to sizeof(ADDRINT) in size
ADDRINT mem_val(ADDRINT addr, size_t size)
{
    ADDRINT ret = 0;

    if (size && (size <= sizeof(ret)))
        PIN_SafeCopy(&ret, (VOID*)addr, size);

    return ret;
}

// Determine if address is an instruction from the main exe's .text segment
bool is_textaddr(ADDRINT addr)
{
    return (text_base <= addr) && (addr < text_end);
}

// Main call entered
VOID main_call(ADDRINT rcx, ADDRINT rdx)
{
    // Save call ID
    ADDRINT ecx = rcx & 0xffffffff;
    call_stack.push_back(ecx);

    main_thread = PIN_GetTid();

    if (search_mode)
        return;

    PIN_LockClient();
    indent();

    if (canonical)
        logfile << "MATRYKA_" << ecx << std::endl;
    else
        logfile << func_start << " (" << realaddr_to_IDA(func_start)
                << ")\tECX=" << ecx
                << "\tRDX=" << rdx
                << "\t[rdx]="   << mem_val(rdx, sizeof(ADDRINT))
                << "\t[rdx+8]=" << mem_val(rdx + 8, sizeof(ADDRINT))
                << std::endl;

    PIN_UnlockClient();
}

// Return from main call
VOID main_ret()
{
    call_stack.pop_back();
}

// Log API calls
VOID log_api(ADDRINT ip, ADDRINT ret_addr)
{
    // Log only APIs returning to .text in main exe
    if (!call_stack.size() || !is_textaddr(ret_addr))
        return;

    PIN_LockClient();
    indent();
    logfile << "***" << api_map[ip] << " returns to " << ret_addr << " (" << realaddr_to_IDA(ret_addr) << ')' << std::endl;
    PIN_UnlockClient();
}

// Log instruction details
VOID log_ins(ADDRINT rip, std::string *disasm, const CONTEXT *ctxt)
{
    // Labels and constants needed for logging register values
    static const char reg_labels[16][8] =
    { "RAX=", ", RCX=", ", RDX=", ", RBX=",
      ", RSI=", ", RDI=", ", RSP=", ", RBP=",
      ", R8=", ", R9=", ", R10=", ", R11=",
      ", R12=", ", R13=", ", R14=", ", R15=" };

    static const REG reg_consts[16] =
    { REG_GAX, REG_GBX, REG_GDX, REG_GBX,
      REG_GSI, REG_GDI, REG_RSP, REG_GBP,
      REG_R8, REG_R9, REG_R10, REG_R11,
      REG_R12, REG_R13, REG_R14, REG_R15 };

    if (search_mode && (search_addrs.find(realaddr_to_IDA(rip)) != search_addrs.end()))
    {
        PIN_LockClient();
        logfile << rip << " (" << realaddr_to_IDA(rip) << ")\t" << *disasm;
        pad_ins(disasm->size());
        logfile << "MATRYKA_" << call_stack.back() << std::endl;
        PIN_UnlockClient();

        search_addrs.erase(realaddr_to_IDA(rip));
        return;
    }

    // Log instructions only for sections specified with -d option
    if ((PIN_GetTid() != main_thread) ||
        detailed_calls.find(call_stack.back()) == detailed_calls.end())
        return;

    PIN_LockClient();
    indent();

    logfile << rip << " (" << realaddr_to_IDA(rip) << ")\t" << *disasm;
    pad_ins(disasm->size());

    for (size_t i = 0; i < 16; i++)
        logfile << reg_labels[i] << PIN_GetContextReg(ctxt, reg_consts[i]);

    logfile << std::endl;
    PIN_UnlockClient();
}

// Log memory reads and writes
VOID log_readwrite(ADDRINT rip, ADDRINT ea, size_t size, bool is_read)
{
    // Log only for sections specified with -d option
    if ((PIN_GetTid() != main_thread) ||
        detailed_calls.find(call_stack.back()) == detailed_calls.end())
        return;

    PIN_LockClient();
    indent();
    
    logfile << rip << ((is_read) ? "\tREAD " : "\tWROTE ")
             << (size & 0xff) << " bytes [" << ea << "]  " << mem_val(ea, size & 0xff) << std::endl;

    PIN_UnlockClient();
}

// Instrument modules on load
VOID imgInstrumentation(IMG img, VOID* val)
{
    // Instrument all APIs
    if (!IMG_IsMainExecutable(img))
    {
        if (!search_mode)
        {
            std::string img_name = IMG_Name(img);
            indent();
            logfile << "Loaded module " << img_name << " at " << IMG_LowAddress(img) << std::endl;

            for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
            {
                for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
                {
                    ADDRINT addr = RTN_Address(rtn);
                    api_map[addr] = img_name + '!' + RTN_Name(rtn);

                    if ((api_map[addr] != ".text") && (api_map[addr] != "unnamedImageEntryPoint"))
                    {
                        // Instrument entry to API call
                        RTN_Open(rtn);
                        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)log_api, IARG_INST_PTR, IARG_RETURN_IP, IARG_END);
                        RTN_Close(rtn);
                    }
                }
            }
        }
    }
    else
    {
        logfile << "Loaded main module " << IMG_Name(img) << " at " << IMG_LowAddress(img) << std::endl;

        // Multiple .text entries are sometimes found
        // Only care about the first one
        bool text_mapped = false;

        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec) && !text_mapped; sec = SEC_Next(sec))
        {
            for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
            {
                ADDRINT addr = RTN_Address(rtn);

                if (RTN_Name(rtn) == ".text")
                {
                    // Save real mapped addresses
                    text_base = RTN_Address(rtn);
                    text_end = text_base + RTN_Size(rtn);

                    func_start = IDA_to_realaddr(func_start);
                    func_ret = IDA_to_realaddr(func_ret);

                    logfile << "text base:        " << text_base << " (" << realaddr_to_IDA(text_base)  << ")\n";
                    logfile << "function start:   " << func_start << " (" << realaddr_to_IDA(func_start) << ")\n";
                    logfile << "function return:  " << func_ret << " (" << realaddr_to_IDA(func_ret) << ")\n" << std::endl;

                    text_mapped = true;
                    break;
                }
            }
        }
    }
}

// Instrument instructions
VOID insInstrumentation(INS ins, VOID* v)
{
    static bool main_found = false;
    ADDRINT addr = INS_Address(ins);

    if (addr == func_start)
    {
        main_found = true;

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)main_call,
            IARG_REG_VALUE, REG_RCX,
            IARG_REG_VALUE, REG_RDX,
            IARG_END);
    }

    // Only use detailed logging for .text instructions
    if (main_found && detailed_calls.size() && is_textaddr(addr))
    {
        // Detailed logging for each instruction
        // The "new std::string" construct is nightmare fuel, but Intel has used it before in examples,
        // and won't lead to leaks as long as we plan not to remove any instrumentation later
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log_ins,
            IARG_INST_PTR,
            IARG_ADDRINT, new std::string(INS_Disassemble(ins)),
            IARG_CONST_CONTEXT,
            IARG_END);

        // Insert calls to log memory reads and writes
        UINT32 memOperands = INS_MemoryOperandCount(ins);

        for (UINT32 memOp = 0; memOp < memOperands; memOp++)
        {
            const UINT32 size = INS_MemoryOperandSize(ins, memOp);

            if (INS_MemoryOperandIsRead(ins, memOp))
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log_readwrite,
                    IARG_INST_PTR,
                    IARG_MEMORYOP_EA, memOp,
                    IARG_ADDRINT, size,
                    IARG_BOOL, TRUE,        // is_read
                    IARG_END);

            if (INS_MemoryOperandIsWritten(ins, memOp) && INS_IsValidForIpointAfter(ins))
                INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)log_readwrite,
                    IARG_INST_PTR,
                    IARG_MEMORYOP_EA, memOp,
                    IARG_ADDRINT, size,
                    IARG_BOOL, FALSE,        // is_read
                    IARG_END);
        }
    }
    else if (search_mode && (search_addrs.find(realaddr_to_IDA(addr)) != search_addrs.end()))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log_ins,
            IARG_INST_PTR,
            IARG_ADDRINT, new std::string(INS_Disassemble(ins)),
            IARG_CONST_CONTEXT,
            IARG_END);
    }

    if (addr == func_ret)
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)main_ret, IARG_END);
}

// Called on program exit
VOID finished(INT32 code, VOID* v)
{
    logfile << "Finished" << std::endl;
    logfile.close();
}

// Parse option argument lists
void parse_arg_list(std::set<ADDRINT>& out, const std::string& in)
{
    std::istringstream ss(in);
    std::string token;

    while (std::getline(ss, token, ','))
    {
        char *end = (char*) token.c_str() + token.size();
        out.insert(strtoull(token.c_str(), &end, 16));
    }
}

int main(int argc, char* argv[])
{
    // Init PIN
    PIN_InitSymbols();

    // Parse command line
    if (PIN_Init(argc, argv))
        return -1;

    // Open log file
    logfile.open(opt_logfile.Value().c_str());

    // Exit if unable to open log file
    if (!logfile)
    {
        PIN_CRITICAL_ERROR("ERROR:  Failed to open log file!");
        return -1;
    }

    // Use of canonical call names
    canonical = opt_canonical.Value();

    if (opt_searchaddrs.Value().size())
    {
        parse_arg_list(search_addrs, opt_searchaddrs.Value());
        search_mode = true;
    }
    else
        parse_arg_list(detailed_calls, opt_detailedcalls.Value());

    // Setup PIN instrumentation callbacks
    INS_AddInstrumentFunction(insInstrumentation, 0);
    IMG_AddInstrumentFunction(imgInstrumentation, 0);
    PIN_AddFiniFunction(finished, 0);

    // Start analysis
    logfile << std::hex;
    PIN_StartProgram();

    return 0;
}
