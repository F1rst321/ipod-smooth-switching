// Locate defined store instructions that encode a selected ARM immediate.
// This narrows static tracing when a structure field is written through an
// unknown register; every hit still needs register/data-flow analysis.
// @category iPodCrossfade

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.address.AddressSetView;

public class FindByteStoreOffset extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("Supply one immediate, e.g. 0xc8");
        }

        long wanted = Long.decode(args[0]);
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int hits = 0;
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            AddressSetView body = function.getBody();
            for (Instruction instruction : currentProgram.getListing()
                    .getInstructions(body, true)) {
                String mnemonic = instruction.getMnemonicString().toUpperCase();
                if (!mnemonic.startsWith("STR")) {
                    continue;
                }

                boolean immediateMatch = false;
                for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                    for (Object value : instruction.getOpObjects(operand)) {
                        if (value instanceof Scalar
                                && ((Scalar) value).getUnsignedValue() == wanted) {
                            immediateMatch = true;
                        }
                    }
                }

                if (immediateMatch) {
                    println(String.format("%s  %s  in %s @ %s",
                            instruction.getAddress(), instruction,
                            function.getName(), function.getEntryPoint()));
                    hits++;
                }
            }
        }
        println(String.format("Store instructions containing immediate 0x%x: %d",
                wanted, hits));
        println("Hits are candidates only; verify the base register and reaching value.");
    }
}
