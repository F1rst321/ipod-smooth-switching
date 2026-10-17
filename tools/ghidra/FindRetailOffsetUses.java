// List analyzed instructions whose scalar operands match an OSOS structure-offset range.
// Usage: FindRetailOffsetUses.java 0xb50 0xb80 -scriptPath tools/ghidra
// @category iPodCrossfade

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;

public class FindRetailOffsetUses extends GhidraScript {
    private static final long BASE = 0x10000000L;

    @Override
    public void run() throws Exception {
        if (!"osos.bin".equals(currentProgram.getName())) {
            throw new IllegalStateException("This script expects the exact extracted osos.bin");
        }
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("Supply inclusive start and exclusive end scalar values");
        }
        long start = Long.decode(args[0]);
        long end = Long.decode(args[1]);
        if (start < 0 || end <= start || end > 0x10000) {
            throw new IllegalArgumentException("Invalid scalar range");
        }

        int matches = 0;
        var functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            var instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                boolean matched = false;
                for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                    for (Object value : instruction.getOpObjects(operand)) {
                        if (value instanceof Scalar scalar) {
                            long candidate = scalar.getUnsignedValue();
                            if (candidate >= start && candidate < end) {
                                matched = true;
                                break;
                            }
                        }
                    }
                    if (matched) break;
                }
                if (matched) {
                    println(String.format("OSOS+0x%06x  function OSOS+0x%06x  %s",
                            instruction.getAddress().getOffset() - BASE,
                            function.getEntryPoint().getOffset() - BASE,
                            instruction));
                    matches++;
                }
            }
        }
        println(String.format("Scalar operand matches in [0x%x,0x%x): %d", start, end, matches));
    }
}
