// Decompile named OSOS offsets in a local, read-only Ghidra project.
// Invoke with analyzeHeadless ... -process osos.bin -postScript
// DumpRetailFunctions.java 0x25a614 0x24a024 -scriptPath tools/ghidra
// @category iPodCrossfade

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class DumpRetailFunctions extends GhidraScript {
    // BinaryLoader maps bytes at the requested base; Ghidra's imageBase is zero,
    // so OSOS-relative offsets must be translated through this block start.
    private static final long BASE = 0x10000000L;
    private static final long OSOS_SIZE = 7_561_216L;

    @Override
    public void run() throws Exception {
        if (!"osos.bin".equals(currentProgram.getName())) {
            throw new IllegalStateException("This script expects the exact extracted osos.bin");
        }
        long memoryBase = currentProgram.getMemory().getMinAddress().getOffset();
        String language = currentProgram.getLanguageID().getIdAsString();
        println(String.format("Program memory base: 0x%x; image base: 0x%x; language: %s",
                memoryBase, currentProgram.getImageBase().getOffset(), language));
        for (ghidra.program.model.mem.MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            println(String.format("Memory block %s: 0x%x..0x%x", block.getName(),
                    block.getStart().getOffset(), block.getEnd().getOffset()));
        }
        if (memoryBase != BASE || !language.startsWith("ARM:LE:32:")) {
            throw new IllegalStateException("Unexpected OSOS base/language: 0x" +
                    Long.toHexString(memoryBase) + " / " + language);
        }
        String[] offsets = getScriptArgs();
        if (offsets.length == 0) {
            throw new IllegalArgumentException("Supply at least one OSOS byte offset");
        }
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Could not open Ghidra decompiler");
        }
        try {
            for (String value : offsets) {
                if (value.startsWith("xref_")) {
                    long offset = Long.decode(value.substring("xref_".length()));
                    if (offset < 0 || offset >= OSOS_SIZE) {
                        throw new IllegalArgumentException("Offset outside OSOS: " + value);
                    }
                    Address target = toAddr(BASE + offset);
                    println(String.format("=== XREFS TO OSOS+0x%x ===", offset));
                    ReferenceIterator references = currentProgram.getReferenceManager()
                            .getReferencesTo(target);
                    int count = 0;
                    while (references.hasNext() && count < 500) {
                        Reference reference = references.next();
                        Function fromFunction = currentProgram.getFunctionManager()
                                .getFunctionContaining(reference.getFromAddress());
                        println(String.format("%s from %s (%s)", reference.getFromAddress(),
                                fromFunction == null ? "<no function>" : fromFunction.getEntryPoint(),
                                reference.getReferenceType()));
                        count++;
                    }
                    println("Reference count printed: " + count);
                    continue;
                }
                long offset = Long.decode(value);
                if (offset < 0 || offset >= OSOS_SIZE) {
                    throw new IllegalArgumentException("Offset outside OSOS: " + value);
                }
                Address address = toAddr(BASE + offset);
                Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
                if (function == null) {
                    disassemble(address);
                    function = createFunction(address, null);
                }
                if (function == null) {
                    println(String.format("OSOS+0x%x: no function could be defined", offset));
                    continue;
                }
                println(String.format("=== OSOS+0x%x (function %s) ===", offset,
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
