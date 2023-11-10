#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>

// Call ID to start and stop write logging upon entry
// We are only interested in the first iteration of MATRYKA_5,
// so we can stop logging on the second encounter
constexpr ADDRINT WRITELOG_STARTSTOP = 5;

// Command line options
KNOB<std::string> opt_logfile(KNOB_MODE_WRITEONCE, "pintool", "o", "loop_writes.txt", "Output log file");

std::ofstream logfile;

// Execution environment information
constexpr ADDRINT IDA_BASE = 0x140001000;
ADDRINT text_base = 0, func_start = 0x140001000, func_ret = 0x140002E07;

OS_THREAD_ID main_thread = 0;
bool loading_done = false;

// Keep up with nested call IDs
std::vector<ADDRINT> call_stack;

// Store write operation information
struct write_info
{
    ADDRINT section, rip, size, data;
};

std::map<ADDRINT, write_info> saved_writes;
bool log_writes = false;

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

// Provide spacing for log_clusters
std::string spacing(size_t length)
{
    return std::string(length, ' ');
}

// Log memory write data clusters
void log_clusters()
{
    logfile << "Mem Addr      RIP                         In Call     Size   Hex             Ascii" << std::endl;

    for (auto it = saved_writes.begin(); it != saved_writes.end(); it++)
    {
        logfile << it->first << spacing(4)
            << it->second.rip << " (" << realaddr_to_IDA(it->second.rip) << ")    "
            << "MATRYKA_" << it->second.section << spacing((it->second.section < 0x10) ? 5 : 4)
            << it->second.size << spacing(4)
            << it->second.data;
        
        if ((it->second.size <= 2) && (it->second.data & 0xff))
            logfile << spacing((it->second.size < 0x10) ? 15 : 14) << (char)(it->second.data & 0xff);

        logfile << std::endl;
    }

    PIN_ExitApplication(0);
}

// Main function entrypoint
VOID main_call(ADDRINT rcx, ADDRINT rdx)
{
    // Set main thread ID to make sure we're not logging worker pool threads
    main_thread = PIN_GetTid();

    // Save call ID
    ADDRINT ecx = rcx & 0xffffffff;
    call_stack.push_back(ecx);

    main_thread = PIN_GetTid();

    // Log writes starting from the first loop
    if (ecx == WRITELOG_STARTSTOP)
    {
        if (!log_writes)
            log_writes = true;
        else
            log_clusters();
    }
}

// Main function return
VOID main_ret()
{
    // Decrease line indentation for nested calls
    call_stack.pop_back();
}

// Record memory writes for sections being examined
VOID log_write(ADDRINT rip, ADDRINT ea, size_t size)
{
    // Only log writes from main thread during the first loop
    if ((PIN_GetTid() != main_thread) || !log_writes)
        return;

    size = size & 0xff;

    write_info w_info;
    w_info.rip = rip;
    w_info.section = call_stack.back();
    w_info.data = mem_val(ea, size);
    w_info.size = size;

    saved_writes[ea] = w_info;
}

// Instrument modules on load
VOID imgInstrumentation(IMG img, VOID* val)
{
    // Instrument all APIs
    if (IMG_IsMainExecutable(img))
    {
        logfile << "Loaded main module " << IMG_Name(img) << " at " << IMG_LowAddress(img) << '\n' << std::endl;

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
                    text_base = RTN_Address(rtn);
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
    ADDRINT addr = INS_Address(ins);

    // Insert main function entry call
    if (addr == func_start)
    {
        loading_done = true;

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)main_call,
            IARG_REG_VALUE, REG_RCX,
            IARG_REG_VALUE, REG_RDX,
            IARG_END);
    }

    // Insert detailed section logging calls
    if (loading_done)
    {
        // Insert calls to log memory writes
        UINT32 memOperands = INS_MemoryOperandCount(ins);

        for (UINT32 memOp = 0; memOp < memOperands; memOp++)
        {
            const UINT32 size = INS_MemoryOperandSize(ins, memOp);

            if (INS_MemoryOperandIsWritten(ins, memOp) && INS_IsValidForIpointAfter(ins))
                INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)log_write,
                    IARG_INST_PTR,
                    IARG_MEMORYOP_EA, memOp,
                    IARG_ADDRINT, size,
                    IARG_END);
        }
    }

    // Insert main function return call
    if (addr == func_ret)
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)main_ret, IARG_END);
}

// Called on program exit
VOID finished(INT32 code, VOID* v)
{
    logfile << "Finished" << std::endl;
    logfile.close();
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

    // Setup PIN instrumentation callbacks
    INS_AddInstrumentFunction(insInstrumentation, 0);
    IMG_AddInstrumentFunction(imgInstrumentation, 0);
    PIN_AddFiniFunction(finished, 0);

    // Start analysis
    logfile << std::hex;
    PIN_StartProgram();

    return 0;
}
