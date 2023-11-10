#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>

// Instruction conducting string write operations we want to examine
// 14000142f mov    [rax], cx
ADDRINT WRITE_RIP = 0x14000142f;

// Command line options
KNOB<std::string> opt_logfile(KNOB_MODE_WRITEONCE, "pintool", "o", "proc_strings.txt", "Output log file");

std::ofstream logfile;

// Execution environment information
constexpr ADDRINT IDA_BASE = 0x140001000;
ADDRINT text_base = 0, func_start = 0x140001000, func_ret = 0x140002E07;

// Keep up with nested call IDs
std::vector<ADDRINT> call_stack;

// String decoding
std::string cur_decoded;

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

// Log decoded strings up to the current point
void log_decoded()
{
    if (cur_decoded.size())
    {
        PIN_LockClient();
        indent();
        logfile << cur_decoded << std::endl;
        PIN_UnlockClient();

        cur_decoded = '\t';
    }
}

// Instrument WRITE_RIP to log byte from cl being written
void decoded_char(ADDRINT rcx)
{
    char c = rcx & 0xff;

    if (c == 0)
    {
        cur_decoded += '\n';

        for (size_t i = 0; i < call_stack.size() - 1; i++)
            cur_decoded += '\t';
    }
    else
        cur_decoded += c;
}

// Main call entered
VOID main_call(ADDRINT rcx, ADDRINT rdx)
{
    // Save call ID
    ADDRINT ecx = rcx & 0xffffffff;
    call_stack.push_back(ecx);

    // Log decoded strings once loops complete
    if ((ecx == 5) || (ecx == 0xe))
        log_decoded();

    PIN_LockClient();
    indent();
    logfile << "MATRYKA_" << ecx << std::endl;
    PIN_UnlockClient();
}

// Return from main call
VOID main_ret()
{
    // Decrease line indentation for nested calls
    call_stack.pop_back();
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
                    WRITE_RIP = IDA_to_realaddr(WRITE_RIP);

                    logfile << "text base:        " << text_base << " (" << realaddr_to_IDA(text_base)  << ")\n";
                    logfile << "function start:   " << func_start << " (" << realaddr_to_IDA(func_start) << ")\n";
                    logfile << "function return:  " << func_ret << " (" << realaddr_to_IDA(func_ret) << ")\n";
                    logfile << "function return:  " << WRITE_RIP << " (" << realaddr_to_IDA(WRITE_RIP) << ")\n" << std::endl;

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
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)main_call,
            IARG_REG_VALUE, REG_RCX,
            IARG_REG_VALUE, REG_RDX,
            IARG_END);
    }
    else if (addr == WRITE_RIP)
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)decoded_char, IARG_REG_VALUE, REG_GCX, IARG_END);
    else if (addr == func_ret)
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
