// Find short ARM sequences that calculate a structure field address and then
// store through it.  This complements immediate-offset STR searches; results
// are candidates and still require object/data-flow validation.
// @category iPodCrossfade

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.lang.Register;
import ghidra.program.model.scalar.Scalar;

public class FindCalculatedOffsetStores extends GhidraScript {
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
                if (!instruction.getMnemonicString().toUpperCase().startsWith("ADD")) {
                    continue;
                }

                Register destination = null;
                long addImmediate = -1;
                for (Object value : instruction.getOpObjects(0)) {
                    if (value instanceof Register) {
                        destination = (Register) value;
                    }
                }
                for (int operand = 1; operand < instruction.getNumOperands(); operand++) {
                    for (Object value : instruction.getOpObjects(operand)) {
                        if (value instanceof Scalar) {
                            addImmediate = ((Scalar) value).getUnsignedValue();
                        }
                    }
                }
                if (destination == null || addImmediate < 0 || addImmediate > wanted) {
                    continue;
                }

                Instruction following = instruction;
                for (int distance = 1; distance <= 4; distance++) {
                    following = currentProgram.getListing()
                            .getInstructionAfter(following.getAddress());
                    if (following == null || !body.contains(following.getAddress())) {
                        break;
                    }
                    if (!following.getMnemonicString().toUpperCase().startsWith("STR")) {
                        continue;
                    }
                    boolean storesThroughDestination = false;
                    long storeImmediate = 0;
                    for (Object value : following.getOpObjects(1)) {
                        if (value instanceof Scalar) {
                            storeImmediate = ((Scalar) value).getUnsignedValue();
                        }
                        if (value instanceof Register) {
                            if (destination.equals(value)) {
                                storesThroughDestination = true;
                            }
                        }
                    }
                    if (storesThroughDestination && addImmediate + storeImmediate == wanted) {
                        println(String.format("%s  %s  + 0x%x -> %s  in %s @ %s",
                                instruction.getAddress(), instruction, storeImmediate, following,
                                function.getName(), function.getEntryPoint()));
                        hits++;
                        break;
                    }
                }
            }
        }
        println(String.format("Calculated-address store candidates for 0x%x: %d",
                wanted, hits));
        println("A matching register is not proof that the structure base is TPCMQUEUE.");
    }
}
