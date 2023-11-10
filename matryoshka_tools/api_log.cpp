#include "pin.H"
#include <iostream>
#include <fstream>
#include <map>

// Output log file
KNOB<std::string> opt_logfile(KNOB_MODE_WRITEONCE, "pintool", "o", "log.txt", "log file");
KNOB<ADDRINT> opt_log_baseaddr(KNOB_MODE_WRITEONCE, "pintool", "b", "0x14000000", "exe base address");
KNOB<BOOL> opt_quiet(KNOB_MODE_WRITEONCE, "pintool", "q", "0", "quiet - log only APIs returning to exe");

// Globals
std::ofstream logfile;
ADDRINT log_baseaddr = 0x14000000, real_baseaddr = 0, real_exe_highaddr = 0;
bool quiet = false;

// API map
std::map<ADDRINT, std::string> api_map;

ADDRINT real_to_logaddr(ADDRINT realaddr)
{
    return realaddr - real_baseaddr + log_baseaddr;
}

bool is_mainexe_addr(ADDRINT addr)
{
    return (real_baseaddr <= addr) && (addr < real_exe_highaddr);
}

VOID log_api(ADDRINT ip, ADDRINT ret_addr)
{
    bool is_main = is_mainexe_addr(ret_addr);

    if (!quiet || is_main)
    {
        PIN_LockClient();
        logfile << api_map[ip] << " returns to " << ret_addr;

        if (is_main)
            logfile << " (" << real_to_logaddr(ret_addr) << ')';

        logfile << std::endl;
        PIN_UnlockClient();
    }
}

// Instrument modules on load
VOID imgInstrumentation(IMG img, VOID* val)
{
    // Instrument all APIs
    if (!IMG_IsMainExecutable(img))
    {
        std::string img_name = IMG_Name(img);
        ADDRINT img_addr = IMG_LowAddress(img);

        if (!quiet)
            logfile << "Loaded module " << img_name << " at " << img_addr << std::endl;

        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
        {
            for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
            {
                ADDRINT rtn_addr = RTN_Address(rtn);
                api_map[rtn_addr] = img_name + '!' + RTN_Name(rtn);

                if ((RTN_Name(rtn) != ".text") && (RTN_Name(rtn) != "unnamedImageEntryPoint"))
                {
                    RTN_Open(rtn);
                    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)log_api, IARG_INST_PTR, IARG_RETURN_IP, IARG_END);
                    RTN_Close(rtn);
                }
            }
        }
    }
    else
    {
        SEC last_sec = IMG_SecTail(img);

        real_exe_highaddr = SEC_Address(last_sec) + SEC_Size(last_sec);
        real_baseaddr = IMG_LowAddress(img);

        logfile << "Loaded main module " << IMG_Name(img) << " at " << real_baseaddr << " (" << real_to_logaddr(real_baseaddr) << ')' << std::endl;
    }
}

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
        LOG("ERROR:  Failed to open log file!");
        return -1;
    }

    log_baseaddr = opt_log_baseaddr.Value();
    quiet = opt_quiet.Value();

    // Setup PIN instrumentation callbacks
    IMG_AddInstrumentFunction(imgInstrumentation, 0);
    PIN_AddFiniFunction(finished, 0);

    // Start analysis
    logfile << "Logging API Calls...\n" << std::hex << std::endl;
    PIN_StartProgram();

    return 0;
}
