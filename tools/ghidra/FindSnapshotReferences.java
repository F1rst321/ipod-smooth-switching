// Print references to absolute addresses in an imported 32 MiB PP502x RAM snapshot.
// Usage: FindSnapshotReferences.java 0x10936ad0 0x10127df4 -scriptPath tools/ghidra
// @category iPodCrossfade

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindSnapshotReferences extends GhidraScript {
    private static final long BASE = 0x10000000L;
    private static final long RAM_SIZE = 0x02000000L;

    @Override
    public void run() throws Exception {
        long memoryBase = currentProgram.getMemory().getMinAddress().getOffset();
        String language = currentProgram.getLanguageID().getIdAsString();
        if (memoryBase != BASE || !language.startsWith("ARM:LE:32:v4t")) {
            throw new IllegalStateException("Expected a PP502x RAM snapshot at 0x10000000");
        }

        String[] args = getScriptArgs();
        if (args.length == 0) {
            throw new IllegalArgumentException("Supply one or more absolute target addresses");
        }

        for (String value : args) {
            long absolute = Long.decode(value);
            if (absolute < BASE || absolute >= BASE + RAM_SIZE) {
                throw new IllegalArgumentException("Address outside PP RAM: " + value);
            }
            Address target = toAddr(absolute);
            println(String.format("=== References to RAM 0x%08x ===", absolute));
            ReferenceIterator references = currentProgram.getReferenceManager()
                    .getReferencesTo(target);
            int count = 0;
            while (references.hasNext() && count < 500) {
                Reference reference = references.next();
                Address from = reference.getFromAddress();
                Function function = currentProgram.getFunctionManager()
                        .getFunctionContaining(from);
                Instruction instruction = currentProgram.getListing()
                        .getInstructionAt(from);
                println(String.format("%s <- %s (%s; %s; %s)", target, from,
                        reference.getReferenceType(),
                        function == null ? "<no function>" : function.getEntryPoint(),
                        instruction == null ? "<no instruction>" : instruction));
                count++;
            }
            println("Reference count printed: " + count);
        }
    }
}
