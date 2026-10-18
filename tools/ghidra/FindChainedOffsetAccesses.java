// Find field accesses formed by a short chain of ARM ADD/MOV instructions.
// Candidates still require object-base and control-flow validation.
// @category iPodCrossfade

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.lang.Register;
import ghidra.program.model.scalar.Scalar;

import java.util.HashMap;
import java.util.Map;

public class FindChainedOffsetAccesses extends GhidraScript {
    private static final class Offset {
        final Register root;
        final long value;

        Offset(Register root, long value) {
            this.root = root;
            this.value = value;
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("Supply one structure offset, e.g. 0x3b9c");
        }
        long wanted = Long.decode(args[0]);
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int storeHits = 0;
        int callHits = 0;

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            Map<Register, Offset> offsets = new HashMap<>();
            for (Instruction instruction : currentProgram.getListing()
                    .getInstructions(function.getBody(), true)) {
                String mnemonic = instruction.getMnemonicString().toUpperCase();
                if (mnemonic.equals("BL") || mnemonic.equals("BLX")) {
                    for (int index = 0; index < 4; index++) {
                        Register argument = currentProgram.getLanguage()
                                .getRegister("r" + index);
                        Offset argumentOffset = offsets.get(argument);
                        if (argumentOffset != null && argumentOffset.value == wanted) {
                            println(String.format(
                                    "%s  %s  arg=r%d root=%s+0x%x  in %s @ %s",
                                    instruction.getAddress(), instruction, index,
                                    argumentOffset.root, argumentOffset.value,
                                    function.getName(), function.getEntryPoint()));
                            callHits++;
                        }
                    }
                    offsets.clear();
                    continue;
                }
                if (mnemonic.equals("B") ||
                        (mnemonic.startsWith("B") && !mnemonic.startsWith("BIC") &&
                                !mnemonic.startsWith("BFC") && !mnemonic.startsWith("BFI"))) {
                    offsets.clear();
                    continue;
                }

                Register destination = registerOperand(instruction, 0);
                if (mnemonic.startsWith("STR")) {
                    Register base = registerOperand(instruction, 1);
                    long memoryOffset = scalarOperand(instruction, 1);
                    Offset baseOffset = offsets.get(base);
                    if (base != null && baseOffset != null &&
                            baseOffset.value + memoryOffset == wanted) {
                        println(String.format(
                                "%s  %s  root=%s+0x%x  in %s @ %s",
                                instruction.getAddress(), instruction,
                                baseOffset.root, baseOffset.value + memoryOffset,
                                function.getName(), function.getEntryPoint()));
                        storeHits++;
                    }
                }

                if (destination == null) {
                    continue;
                }
                if (mnemonic.startsWith("ADD") && instruction.getNumOperands() >= 3) {
                    Register source = registerOperand(instruction, 1);
                    long immediate = scalarOperand(instruction, 2);
                    Offset sourceOffset = offsets.get(source);
                    if (sourceOffset == null && source != null) {
                        sourceOffset = new Offset(source, 0);
                    }
                    if (sourceOffset != null) {
                        offsets.put(destination,
                                new Offset(sourceOffset.root, sourceOffset.value + immediate));
                    } else {
                        offsets.remove(destination);
                    }
                } else if (mnemonic.startsWith("MOV")) {
                    Register source = registerOperand(instruction, 1);
                    Offset sourceOffset = offsets.get(source);
                    if (sourceOffset == null && source != null) {
                        sourceOffset = new Offset(source, 0);
                    }
                    if (sourceOffset != null) {
                        offsets.put(destination, sourceOffset);
                    } else {
                        offsets.remove(destination);
                    }
                } else {
                    offsets.remove(destination);
                }
            }
        }
        println(String.format("Chained stores to offset 0x%x: %d", wanted, storeHits));
        println(String.format("Calls passing offset 0x%x in r0-r3: %d", wanted, callHits));
        println("Computed register offsets are candidates, not proof of a specific object.");
    }

    private Register registerOperand(Instruction instruction, int operand) {
        if (operand >= instruction.getNumOperands()) {
            return null;
        }
        for (Object value : instruction.getOpObjects(operand)) {
            if (value instanceof Register) {
                return (Register) value;
            }
        }
        return null;
    }

    private long scalarOperand(Instruction instruction, int operand) {
        if (operand >= instruction.getNumOperands()) {
            return 0;
        }
        for (Object value : instruction.getOpObjects(operand)) {
            if (value instanceof Scalar) {
                return ((Scalar) value).getUnsignedValue();
            }
        }
        return 0;
    }
}
