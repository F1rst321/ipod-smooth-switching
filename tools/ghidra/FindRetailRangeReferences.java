// Check an OSOS byte range for analyzed functions and direct references.
// Usage: FindRetailRangeReferences.java 0x7358c4 0x736000 -scriptPath tools/ghidra
// @category iPodCrossfade

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindRetailRangeReferences extends GhidraScript {
    private static final long BASE = 0x10000000L;
    private static final long OSOS_SIZE = 7_561_216L;

    @Override
    public void run() throws Exception {
        if (!"osos.bin".equals(currentProgram.getName())) {
            throw new IllegalStateException("This script expects the exact extracted osos.bin");
        }
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("Supply inclusive start and exclusive end OSOS offsets");
        }
        long start = Long.decode(args[0]);
        long end = Long.decode(args[1]);
        if (start < 0 || end <= start || end > OSOS_SIZE) {
            throw new IllegalArgumentException("Invalid OSOS range");
        }

        int functionHits = 0;
        int referenceHits = 0;
        for (long offset = start; offset < end; offset++) {
            Address address = toAddr(BASE + offset);
            if ((offset & 3) == 0) {
                Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
                if (function != null) {
                    println(String.format("FUNCTION OSOS+0x%06x in OSOS+0x%06x",
                            offset, function.getEntryPoint().getOffset() - BASE));
                    functionHits++;
                }
            }
            ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(address);
            while (references.hasNext()) {
                Reference reference = references.next();
                Address from = reference.getFromAddress();
                Function sourceFunction = currentProgram.getFunctionManager()
                        .getFunctionContaining(from);
                Instruction sourceInstruction = currentProgram.getListing().getInstructionAt(from);
                String functionName = sourceFunction == null
                        ? "<no function>"
                        : String.format("OSOS+0x%06x", sourceFunction.getEntryPoint().getOffset() - BASE);
                String instruction = sourceInstruction == null
                        ? "<no instruction>"
                        : sourceInstruction.toString();
                println(String.format("XREF OSOS+0x%06x <- OSOS+0x%06x (%s; %s; %s)", offset,
                        from.getOffset() - BASE, reference.getReferenceType(), functionName,
                        instruction));
                referenceHits++;
            }
        }
        println(String.format("Range OSOS+0x%06x..0x%06x: function-hit addresses=%d; references=%d",
                start, end, functionHits, referenceHits));
    }
}
