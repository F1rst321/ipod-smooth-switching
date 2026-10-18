// Decompile functions from a raw PortalPlayer IRAM snapshot.
// Import with BinaryLoader at 0x40000000 and ARM:LE:32:v4t, then pass absolute
// IRAM addresses such as 0x40000e44 as script arguments.
// @category iPodCrossfade

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DumpIramFunctions extends GhidraScript {
    private static final long BASE = 0x40000000L;
    private static final long IRAM_SIZE = 0x20000L;

    @Override
    public void run() throws Exception {
        long memoryBase = currentProgram.getMemory().getMinAddress().getOffset();
        String language = currentProgram.getLanguageID().getIdAsString();
        println(String.format("IRAM base: 0x%x; language: %s", memoryBase, language));
        if (memoryBase != BASE || !language.startsWith("ARM:LE:32:v4t")) {
            throw new IllegalStateException("Unexpected IRAM base or language");
        }

        String[] args = getScriptArgs();
        if (args.length == 0) {
            throw new IllegalArgumentException("Supply absolute IRAM function addresses");
        }
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Could not open Ghidra decompiler");
        }
        try {
            for (String value : args) {
                long absolute = Long.decode(value);
                if (absolute < BASE || absolute >= BASE + IRAM_SIZE) {
                    throw new IllegalArgumentException("Address outside IRAM: " + value);
                }
                Address address = toAddr(absolute);
                Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
                if (function == null) {
                    disassemble(address);
                    function = createFunction(address, null);
                }
                if (function == null) {
                    println(String.format("0x%x: no function could be defined", absolute));
                    continue;
                }
                println(String.format("=== IRAM 0x%x (function %s) ===", absolute,
                        function.getEntryPoint()));
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                    println("Decompiler failed: " + result.getErrorMessage());
                } else {
                    println(result.getDecompiledFunction().getC());
                }
            }
        } finally {
            decompiler.dispose();
        }
    }
}
