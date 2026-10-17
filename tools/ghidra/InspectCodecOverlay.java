// Reconstruct an audio-provider IRAM overlay in a read-only OSOS project.
// Arguments: provider index, captured IRAM file, runtime function addresses.
// This is a static reconstruction, not evidence of executing a music track.
// @category iPodCrossfade

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HexFormat;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemoryBlock;

public class InspectCodecOverlay extends GhidraScript {
    private static final long OSOS_BASE = 0x10000000L;
    private static final long SOURCE_ALIAS = 0x04000000L;
    private static final long IRAM_BASE = 0x40000000L;
    private static final int IRAM_SIZE = 0x20000;
    private static final int OSOS_SIZE = 7_561_216;
    private static final String STOCK_SHA =
        "784ae3d5540fd2f89e8c947b93629e97f62a06dc311d9745aab143e4db6bb251";

    // Literal locations are taken from the five provider loader routines.
    private static final int[][] COPIES = {
        {0x840d0, 0x840e4, 0x840f8}, {0x8410c}, {0x841c0, 0x841d4},
        {0x84328, 0x8433c, 0x84350}, {0x84314}
    };
    private static final int[][][] CLEARS = {
        {{0x840e0, 0x840dc}, {0x840f4, 0x840f0}, {0x84108, 0x84104}},
        {{0x8411c, 0x84118}},
        {{0x841d0, 0x841cc}, {0x841e4, 0x841e0}},
        {{0x84338, 0x84334}, {0x8434c, 0x84348}, {0x84360, 0x8435c}},
        {{0x84324, 0x84320}}
    };

    private long word(byte[] bytes, int offset) {
        return (bytes[offset] & 255L) | ((bytes[offset + 1] & 255L) << 8)
            | ((bytes[offset + 2] & 255L) << 16) | ((bytes[offset + 3] & 255L) << 24);
    }

    private void requireRange(long offset, long length, int capacity) {
        if (offset < 0 || length < 0 || offset > capacity || length > capacity - offset) {
            throw new IllegalArgumentException("Range exceeds image bounds");
        }
    }

    private void recoverManualCalls(byte[] iram) throws Exception {
        // ARM7 has no BLX-register instruction. RetailOS often uses
        // ADD LR,PC,#8; <two instructions>; BX Rn. LR then equals BX+4.
        // Only repair already-disassembled BX instructions with that exact
        // return-address pattern and no intervening LR/PC write or branch.
        for (int pass = 0; pass < 64; pass++) {
            ArrayList<Address> repairs = new ArrayList<>();
            var instructions = currentProgram.getListing().getInstructions(toAddr(IRAM_BASE), true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                long address = instruction.getAddress().getOffset();
                if (address >= IRAM_BASE + IRAM_SIZE) break;
                int offset = (int) (address - IRAM_BASE);
                if (offset < 12 || !instruction.getMnemonicString().equalsIgnoreCase("bx") ||
                    instruction.getFlowOverride() != FlowOverride.NONE ||
                    word(iram, offset - 12) != 0xe28fe008L) continue;
                long branch = word(iram, offset);
                if ((branch & 0xfffffff0L) != 0xe12fff10L || (branch & 15) >= 14) continue;
                boolean valid = true;
                for (int back = 8; back >= 4; back -= 4) {
                    Instruction middle = getInstructionAt(toAddr(address - back));
                    if (middle == null || middle.getLength() != 4 ||
                        !middle.getFlowType().isFallthrough()) {
                        valid = false;
                        break;
                    }
                    for (Object result : middle.getResultObjects()) {
                        if (result instanceof Register register &&
                            (register.getName().equalsIgnoreCase("lr") ||
                             register.getName().equalsIgnoreCase("pc") ||
                             register.getName().equalsIgnoreCase("r14") ||
                             register.getName().equalsIgnoreCase("r15"))) valid = false;
                    }
                }
                if (valid) repairs.add(instruction.getAddress());
            }
            if (repairs.isEmpty()) return;
            for (Address address : repairs) {
                getInstructionAt(address).setFlowOverride(FlowOverride.CALL);
                disassemble(address.add(4));
                println("Recovered manual call return at " + address);
            }
        }
        throw new IllegalStateException("Manual-call recovery exceeded its pass limit");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3 || !"osos.bin".equals(currentProgram.getName()) ||
            !currentProgram.getLanguageID().getIdAsString().startsWith("ARM:LE:32:")) {
            throw new IllegalArgumentException("Use an ARM OSOS project; args: provider IRAM-file addresses");
        }
        int provider = Integer.parseInt(args[0]);
        if (provider < 0 || provider >= COPIES.length) {
            throw new IllegalArgumentException("Provider must be 0..4");
        }
        byte[] osos = new byte[OSOS_SIZE];
        int read = currentProgram.getMemory().getBytes(toAddr(OSOS_BASE), osos);
        String sha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(osos));
        if (read != OSOS_SIZE || !STOCK_SHA.equals(sha)) {
            throw new IllegalStateException("OSOS does not match the untouched backup");
        }
        byte[] iram = Files.readAllBytes(Path.of(args[1]));
        if (iram.length != IRAM_SIZE) {
            throw new IllegalArgumentException("Expected a complete 128 KiB IRAM snapshot");
        }
        for (int literal : COPIES[provider]) {
            long source = word(osos, literal) - SOURCE_ALIAS;
            long destination = word(osos, literal + 4) - IRAM_BASE;
            long length = word(osos, literal + 8);
            requireRange(source, length, osos.length);
            requireRange(destination, length, iram.length);
            System.arraycopy(osos, (int) source, iram, (int) destination, (int) length);
            println(String.format("COPY OSOS+0x%x -> IRAM 0x%x length 0x%x",
                source, IRAM_BASE + destination, length));
        }
        for (int[] literals : CLEARS[provider]) {
            long destination = word(osos, literals[0]) - IRAM_BASE;
            long length = word(osos, literals[1]);
            requireRange(destination, length, iram.length);
            Arrays.fill(iram, (int) destination, (int) (destination + length), (byte) 0);
        }

        // A conflicting block is an error; never replace existing project memory.
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (block.getStart().getOffset() < IRAM_BASE + IRAM_SIZE &&
                block.getEnd().getOffset() >= IRAM_BASE) {
                throw new IllegalStateException("Project already contains IRAM memory");
            }
        }
        MemoryBlock block = currentProgram.getMemory().createInitializedBlock(
            "codec_iram", toAddr(IRAM_BASE), new ByteArrayInputStream(iram),
            iram.length, monitor, false);
        block.setRead(true);
        block.setWrite(true);
        block.setExecute(true);

        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Cannot open decompiler");
        }
        try {
            for (int index = 2; index < args.length; index++) {
                long runtime = Long.decode(args[index]);
                requireRange(runtime - IRAM_BASE, 4, IRAM_SIZE);
                Address address = toAddr(runtime);
                disassemble(address);
                recoverManualCalls(iram);
                Function function = getFunctionAt(address);
                if (function == null) {
                    function = createFunction(address, null);
                }
                if (function == null) {
                    println("No function could be created at " + address);
                    continue;
                }
                println("=== reconstructed provider " + provider + " IRAM " + address + " ===");
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    println(result.getDecompiledFunction().getC());
                } else {
                    println("Decompiler failed: " + result.getErrorMessage());
                }
            }
        } finally {
            decompiler.dispose();
        }
    }
}
