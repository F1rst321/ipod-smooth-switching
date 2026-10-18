// Print disassembled OSOS instructions for exact offsets in a read-only Ghidra project.
// @category iPodCrossfade

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class DumpRetailListing extends GhidraScript {
    private static final long BASE = 0x10000000L;
    private static final long OSOS_SIZE = 7_561_216L;

    @Override
    public void run() throws Exception {
        if (!"osos.bin".equals(currentProgram.getName())) {
            throw new IllegalStateException("This script expects the exact extracted osos.bin");
        }
        String[] args = getScriptArgs();
        if (args.length < 2 || (args.length % 2) != 0) {
            throw new IllegalArgumentException("Supply offset/count pairs");
        }
        for (int i = 0; i < args.length; i += 2) {
            long offset = Long.decode(args[i]);
            int count = Integer.decode(args[i + 1]);
            if (offset < 0 || offset >= OSOS_SIZE || count < 1 || count > 4096) {
                throw new IllegalArgumentException("Invalid offset/count pair: " + args[i] + "," + args[i + 1]);
            }
            Address address = toAddr(BASE + offset);
            Function owner = currentProgram.getFunctionManager().getFunctionContaining(address);
            Instruction existing = currentProgram.getListing().getInstructionAt(address);
            String ownerOffset = owner == null
                    ? "none"
                    : String.format("OSOS+0x%06x", owner.getEntryPoint().getOffset() - BASE);
            println(String.format("=== OSOS+0x%x (%d instructions; function=%s; already-defined=%s) ===",
                    offset, count, ownerOffset, existing != null));
            int emitted = 0;
            while (emitted < count && address.getOffset() < BASE + OSOS_SIZE) {
                Instruction instruction = currentProgram.getListing().getInstructionAt(address);
                if (instruction == null) {
                    disassemble(address);
                    instruction = currentProgram.getListing().getInstructionAt(address);
                }
                if (instruction == null) {
                    println(String.format("OSOS+0x%06x  <no instruction>", address.getOffset() - BASE));
                    break;
                }
                StringBuilder bytes = new StringBuilder();
                for (byte value : instruction.getBytes()) {
                    if (bytes.length() != 0) bytes.append(' ');
                    bytes.append(String.format("%02x", value & 0xff));
                }
                println(String.format("OSOS+0x%06x  %-23s %s", instruction.getAddress().getOffset() - BASE,
                        bytes, instruction.toString()));
                address = address.add(instruction.getLength());
                emitted++;
            }
        }
    }
}
