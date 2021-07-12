// (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
package chpe;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.util.bin.format.pe.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.QWordDataType;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class ChpeFixup {

    public static class InvalidChpeFixupBlockAlignment extends Exception {
        InvalidChpeFixupBlockAlignment(String msg) {
            super(msg);
        }
    }

    public static class UnknownChpeFixupRelocTypeException extends Exception {
        UnknownChpeFixupRelocTypeException(String msg)  {
            super(msg);
        }
    }

    public static class BrokenChpeFixupRecord extends Exception {
        BrokenChpeFixupRecord(String msg) {
            super(msg);
        }
    }

    public static void tryCreateData(Listing listing, Address addr, DataType dataType) {
        try {
            listing.createData(addr, dataType);
        } catch (CodeUnitInsertionException exp) {
            System.err.println("Data Type has been already set.\n So, skipping");
        }
    }

    public static class ChpeFixupHeader {
        // IMAGE_DYNAMIC_RELOCATION_TABLE
        public int version;
        public int size;

        // IMAGE_DYNAMIC_RELOCATION_ARM64X_HEADER
        public long symbol;
        public int fixupInfoSize;

        public ChpeFixupHeader(Memory memory, Address curAddr) throws MemoryAccessException, InvalidInputException {
            var program = memory.getProgram();
            var listing = program.getListing();
            var symbolTable = program.getSymbolTable();

            symbolTable.createLabel(curAddr, "IMAGE_DYNAMIC_RELOCATION_TABLE", SourceType.USER_DEFINED);
            version = memory.getInt(curAddr);
            tryCreateData(listing, curAddr, new DWordDataType());
            size = memory.getInt(curAddr.add(0x4));
            tryCreateData(listing, curAddr.add(0x4), new DWordDataType());

            symbolTable.createLabel(curAddr.add(0x8), "IMAGE_DYNAMIC_RELOCATION_ARM64X", SourceType.USER_DEFINED);
            symbol = memory.getLong(curAddr.add(0x8));
            tryCreateData(listing, curAddr.add(0x8), new QWordDataType());
            fixupInfoSize = memory.getInt(curAddr.add(0x10));
            tryCreateData(listing, curAddr.add(0x10), new DWordDataType());
        }

        public ChpeFixupHeader(int version_, int size_, long symbol_, int sizeOfChpeFixup_) {
            version = version_;
            size = size_;
            symbol = symbol_;
            fixupInfoSize = sizeOfChpeFixup_;
        }

        public static int getByteSize() {
            return 0x14;
        }

        @Override
        public String toString() {
            return String.format(
                    "version: %x\nsize: %x\nsymbol: %x\nfixupInfoSize: %x\n",
                    version, size, symbol, fixupInfoSize
            );
        }

        public Address exportToMemory(Memory memory, Address at) throws MemoryAccessException {
            memory.setInt(at, version);
            memory.setInt(at.add(0x4), size);
            memory.setLong(at.add(0x8), symbol);
            memory.setInt(at.add(0x10), fixupInfoSize);
            return at.add(getByteSize());
        }
    }

    public static class ChpeFixupRecordZeroFill extends ChpeFixupRecord {
        ChpeFixupRecordZeroFill(Memory memory, Address curAddr, Listing listing) throws MemoryAccessException  {
            super(memory, curAddr, listing);
            relocEntryDataSize = 0;
            final var metaDecoded= decodeSizeMetadata(meta);
            sizeToBeWritten = metaDecoded[1];
        }

        ChpeFixupRecordZeroFill(int metaAndOffset_) {
            super(metaAndOffset_);
            relocEntryDataSize = 0;
            final var metaDecoded = decodeSizeMetadata(meta);
            sizeToBeWritten = metaDecoded[1];
        }

        @Override
        public Optional<Long> data() {
            return Optional.of(0L);
        }

        @Override
        public void applyFixup(Memory memory, Address addrToBeRelocated, Assembler assembler) throws MemoryAccessException, BrokenChpeFixupRecord {
            switch (sizeToBeWritten) {
                case 2:
                    memory.setShort(addrToBeRelocated, (short) 0);
                    break;
                case 4:
                    memory.setInt(addrToBeRelocated, 0);
                    break;
                case 8:
                    memory.setLong(addrToBeRelocated, 0);
                    break;
                default:
                    throw new BrokenChpeFixupRecord("Broken CHPE fixup record " + toString());
            }
        }

        @Override
        public Address exportToMemory(Memory memory, Address at) throws MemoryAccessException {
            memory.setShort(at, (short)(metaAndOffset & 0xffff));
            return at.add(0x2);
        }

        @Override
        public ChpeFixupEntryRaw getRawEntry() {
            return new ChpeFixupEntryRaw(metaAndOffset, 0);
        }
    }

    public static class ChpeFixupRecordAssignValue extends ChpeFixupRecord {
        public Optional<Long> dataToBeWritten;

        ChpeFixupRecordAssignValue(Memory memory, Address curAddr, Listing listing) throws MemoryAccessException  {
            super(memory, curAddr, listing);
            final var metaDecoded = decodeSizeMetadata(meta);
            relocEntryDataSize = metaDecoded[0];
            sizeToBeWritten = metaDecoded[1];

            final var addrContainingData = curAddr.add(0x2);
            switch (relocEntryDataSize) {
                case 2:
                    dataToBeWritten = Optional.of((long) (memory.getShort(addrContainingData) & 0xffff));
                    tryCreateData(listing, addrContainingData, new WordDataType());
                    break;
                case 4:
                    dataToBeWritten = Optional.of((long) (memory.getInt(addrContainingData)));
                    tryCreateData(listing, addrContainingData, new DWordDataType());
                    break;
                case 8:
                    dataToBeWritten = Optional.of((memory.getLong(addrContainingData)));
                    tryCreateData(listing, addrContainingData, new QWordDataType());
                    break;
                default:
                    System.err.println("Something went wrong while processing data at " + addrContainingData.toString());
                    dataToBeWritten = Optional.empty();
                    break;
            }
        }

        ChpeFixupRecordAssignValue(int metaAndOffset_, long dataRaw_) {
            super(metaAndOffset_);
            final var metaDecoded = decodeSizeMetadata(meta);
            relocEntryDataSize = metaDecoded[0];
            sizeToBeWritten = metaDecoded[1];

            switch (relocEntryDataSize) {
                case 2:
                    dataToBeWritten = Optional.of(dataRaw_ & 0xffff);
                    break;
                case 4:
                    dataToBeWritten = Optional.of(dataRaw_ & 0xffffffffL);
                    break;
                case 8:
                    dataToBeWritten = Optional.of(dataRaw_);
                    break;
                default:
                    System.err.println("Decoded metadta is invalid");
                    dataToBeWritten = Optional.empty();
                    break;
            }
        }

        @Override
        public Address exportToMemory(Memory memory, Address at) throws MemoryAccessException {
            if (dataToBeWritten.isEmpty()) {
                System.err.println("The dataToBeWritten is not found. This entry will not be written");
                return null;
            }
            memory.setShort(at, (short)(metaAndOffset & 0xffff));
            switch (relocEntryDataSize) {
                case 2:
                    memory.setShort(at.add(0x2), dataToBeWritten.get().shortValue());
                    return at.add(0x2 + 0x2);
                case 4:
                    memory.setInt(at.add(0x2), dataToBeWritten.get().intValue());
                    return at.add(0x2 + 0x4);
                case 8:
                    memory.setLong(at.add(0x2), dataToBeWritten.get());
                    return at.add(0x2 + 0x8);
                default:
                    System.err.println("relocEntryDataSize valud is invalid");
                    return null;
            }
        }

        @Override
        public ChpeFixupEntryRaw getRawEntry() {
            return new ChpeFixupEntryRaw(metaAndOffset, dataToBeWritten.isEmpty() ? 0 : dataToBeWritten.get());
        }

        @Override
        public Optional<Long> data() {
            return dataToBeWritten;
        }

        @Override
        public void applyFixup(Memory memory, Address addrToBeRelocated, Assembler assembler) throws MemoryAccessException, BrokenChpeFixupRecord {
            try {
                if (dataToBeWritten.isEmpty()) {
                    System.err.println("The data of CHPE fixup is not found. So it will be skipped.");
                    return;
                }
                switch (sizeToBeWritten) {
                    case 2:
                        memory.setShort(addrToBeRelocated, dataToBeWritten.get().shortValue());
                        break;
                    case 4:
                        memory.setInt(addrToBeRelocated, dataToBeWritten.get().intValue());
                        break;
                    case 8:
                        memory.setLong(addrToBeRelocated, dataToBeWritten.get());
                        break;
                    default:
                        throw new BrokenChpeFixupRecord("Broken CHPE fixup record " + toString());
                }
            } catch (MemoryAccessException err) {
                // If memory.set* methods try to write code region, an exception is thrown.
                // In this case, we try to patch instruction through applyPatch method.
                switch (sizeToBeWritten) {
                    case 2:
                        assembler.patchProgram(Utils.shortToBytesArray(dataToBeWritten.get().shortValue()), addrToBeRelocated);
                        break;
                    case 4:
                        assembler.patchProgram(Utils.intToBytesArray(dataToBeWritten.get().intValue()), addrToBeRelocated);
                        break;
                    case 8:
                        assembler.patchProgram(Utils.longToBytesArray(dataToBeWritten.get()), addrToBeRelocated);
                        break;
                    default:
                        break;
                }
            }
        }
    }

    public static class ChpeFixupRecordDelta extends ChpeFixupRecord {
        public int delta;
        public int dataRaw;

        ChpeFixupRecordDelta(Memory memory, Address curAddr, Listing listing) throws MemoryAccessException  {
            super(memory, curAddr, listing);
            final var metaDecoded = decodeSizeMetadata(meta);
            relocEntryDataSize = metaDecoded[0];
            sizeToBeWritten = metaDecoded[1];

            tryCreateData(listing, curAddr.add(2), new WordDataType());
            dataRaw = memory.getShort(curAddr.add(2));
            delta = calcDelta(meta, dataRaw);
        }

        ChpeFixupRecordDelta(int metaAndOffset, int dataRaw) {
            super(metaAndOffset);
            this.dataRaw = dataRaw;
            delta = calcDelta(meta, dataRaw);
        }

        private static int calcDelta(int meta_, int dataRaw_) {
            final var scale = (meta_ & 0b1000) != 0 ?  8 : 4;
            final var sign  = (meta_ & 0b0100) != 0 ? -1 : 1;
            return scale * sign * dataRaw_;
        }

        @Override
        public Optional<Long> data() {
            return Optional.of((long)delta);
        }

        @Override
        public void applyFixup(Memory memory, Address addrToBeRelocated, Assembler assembler) throws MemoryAccessException {
            assert(sizeToBeWritten == 4);
            assert(relocEntryDataSize == 2);

            final var data = memory.getInt(addrToBeRelocated) + delta;
            try {
                memory.setInt(addrToBeRelocated, data);
            } catch (MemoryAccessException err) {
                // If memory.set* methods try to write code region, an exception is thrown.
                // In this case, we try to patch instruction through applyPatch method.
                assembler.patchProgram(Utils.intToBytesArray(data), addrToBeRelocated);
            }
        }

        @Override
        public Address exportToMemory(Memory memory, Address at) throws MemoryAccessException {
            memory.setShort(at, (short)(metaAndOffset & 0xffff));
            memory.setShort(at.add(0x2), (short)(dataRaw & 0xffff));
            return at.add(0x4);
        }

        @Override
        public ChpeFixupEntryRaw getRawEntry() {
            return new ChpeFixupEntryRaw(metaAndOffset, dataRaw);
        }
    }

    abstract public static class ChpeFixupRecord {
        public int metaAndOffset;
        public int meta;
        public int relocEntryDataSize; // NOTE: data size of reloc entry (NOTE: does not include meta|offset size)
        public int sizeToBeWritten;
        public int offset;
        public Address location;
        public ChpeFixupRelocType relocType;

        public static Optional<ChpeFixupRecord> getChpeFixupRecord(Memory memory, Address curAddr, Address nextEntry, Listing listing) throws MemoryAccessException, UnknownChpeFixupRelocTypeException, InvalidChpeFixupBlockAlignment {
            final var metaAndOffset = memory.getShort(curAddr) & 0xffff;
            if (metaAndOffset == 0) {
                if (curAddr.getOffset() + 2 == nextEntry.getOffset()) {
                    tryCreateData(listing, curAddr, new WordDataType());
                    return Optional.empty();
                } else {
                    throw new InvalidChpeFixupBlockAlignment("Alignment seems invalid");
                }
            }
            final var meta = (metaAndOffset & 0xf000) >> 12;
            final var relocType = ChpeFixupRelocType.decodeMetadata(meta);
            switch (relocType)  {
                case ZERO_FILL:
                    return Optional.of(new ChpeFixupRecordZeroFill(memory, curAddr, listing));
                case ASSIGN_VALUE:
                    return Optional.of(new ChpeFixupRecordAssignValue(memory, curAddr, listing));
                case DELTA:
                    return Optional.of(new ChpeFixupRecordDelta(memory, curAddr, listing));
                default:
                    throw new UnknownChpeFixupRelocTypeException("Unknown CHPE fixup metadata 0b11");
            }
        }

        ChpeFixupRecord(Memory memory, Address curAddr, Listing listing) throws MemoryAccessException  {
            metaAndOffset = memory.getShort(curAddr) & 0xffff;
            tryCreateData(listing, curAddr, new WordDataType());
            meta = (metaAndOffset & 0xf000) >> 12;
            offset = metaAndOffset & 0xfff;
            location = curAddr;
            relocType = ChpeFixupRelocType.decodeMetadata(meta);
        }

        ChpeFixupRecord(int metaAndOffset_) {
            metaAndOffset = metaAndOffset_;
            meta = (metaAndOffset & 0xf000) >> 12;
            offset = metaAndOffset & 0xfff;
            relocType = ChpeFixupRelocType.decodeMetadata(meta);
        }

        public abstract Optional<Long> data();
        public abstract void applyFixup(Memory memory, Address addrToBeRelocated, Assembler assembler) throws MemoryAccessException, BrokenChpeFixupRecord;
        public abstract Address exportToMemory(Memory memory, Address at) throws MemoryAccessException;
        public abstract ChpeFixupEntryRaw getRawEntry();
        public int size() {
            return relocEntryDataSize + 2;
        }

        @Override
        public String toString() {
            return String.format(
                    "metaAndOffset: %x\nrelocEntryDataSize: %x\noffset: %x\nlocation: %s\ndata: %s\n",
                    metaAndOffset, relocEntryDataSize, offset, location.toString(),
                    data().map(Long::toHexString).orElse("None")
            );
        }

        public int getByteSize() {
            return 2 + relocEntryDataSize;
        }

        public static int[] decodeSizeMetadata(int meta) {
            // NOTE: [0] relocEntryDataSize, [1] sizeToBeWritten
            if ((meta & 0b11) == 2) {
                return new int[]{2, 4};
            } else {
                final var size = 1 << ((meta & 0b1100) >> 2);
                return new int[]{size, size};
            }
        }
    }

    public enum ChpeFixupRelocType {
        ZERO_FILL,
        ASSIGN_VALUE,
        DELTA,
        UNKNOWN;

        public static ChpeFixupRelocType decodeMetadata(int meta) {
            if ((meta & 0b11) == 0) {
                return ZERO_FILL;
            } else if ((meta & 0b11) == 1) {
                return ASSIGN_VALUE;
            } else if ((meta & 0b11) == 2) {
                return DELTA;
            } else {
                return UNKNOWN;
            }
        }
    }

    private static Address toAddr(Program program, long addrAsLong) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(addrAsLong);
    }

    public static class ChpeFixupBlock {
        public int baseOffset;
        public int blockSize;
        public List<ChpeFixupRecord> records;

        ChpeFixupBlock(Memory memory, Address curAddr) throws MemoryAccessException, UnknownChpeFixupRelocTypeException, InvalidChpeFixupBlockAlignment, InvalidInputException {
            var program = memory.getProgram();
            var listing = program.getListing();
            var symbolTable = program.getSymbolTable();

            symbolTable.createLabel(curAddr, "RELOCATION_BLOCK", SourceType.USER_DEFINED);
            baseOffset = memory.getInt(curAddr);
            tryCreateData(listing, curAddr, new DWordDataType());
            blockSize = memory.getInt(curAddr.add(0x4));
            tryCreateData(listing, curAddr.add(0x4), new DWordDataType());
            records = new ArrayList<>();

            var curAddrLong = curAddr.getOffset() + 0x8;
            final var nextEntryAddr = curAddr.getOffset() + blockSize;
            while (curAddrLong < nextEntryAddr) {
                final var record =
                        ChpeFixupRecord.getChpeFixupRecord(memory, toAddr(program, curAddrLong), toAddr(program, nextEntryAddr), listing);
                if (record.isEmpty()) { // padding
                    break;
                }
                records.add(record.get());
                curAddrLong += record.get().getByteSize();
            }
        }

        public int getByteSize() {
            return blockSize;
        }
    }

    public static ChpeFixupHeader getChpeFixupHeader(PortableExecutable peObj, Program program, TaskMonitor monitor) throws IOException, MemoryAccessException, IllegalAccessException, NoSuchFieldException, InvalidInputException {
        final var chpeBaseAddr = getChpeFixupBaseAddress(peObj, program, monitor);
        var memory = program.getMemory();
        return new ChpeFixupHeader(memory, chpeBaseAddr);
    }

    public static List<ChpeFixupBlock> getChpeFixupBlocks(PortableExecutable peObj, Program program, TaskMonitor monitor) throws MemoryAccessException, IOException, IllegalAccessException, NoSuchFieldException, UnknownChpeFixupRelocTypeException, InvalidChpeFixupBlockAlignment, InvalidInputException {
        final var chpeBaseAddr = getChpeFixupBaseAddress(peObj, program, monitor);
        if (chpeBaseAddr == null) {
            System.err.println("Cannot find CHPE fixup");
            return new ArrayList<>();
        }
        var memory = program.getMemory();
        var header = new ChpeFixupHeader(memory, chpeBaseAddr);

        var chpeFixupBodyStart = chpeBaseAddr.add(header.getByteSize());
        var chpeFixupBodyEnd = chpeFixupBodyStart.add(header.fixupInfoSize);

        var curAddr = chpeFixupBodyStart;

        System.out.println("----------------");
        System.out.println("CHPE fixup header");
        System.out.println(header.toString());
        System.out.println("----------------");

        List<ChpeFixupBlock> chpeFixupBlocks = new ArrayList<>();
        while (curAddr.compareTo(chpeFixupBodyEnd) < 0) {
            System.out.println("Current address is " + curAddr.toString());
            final var block = new ChpeFixupBlock(memory, curAddr);
            curAddr = curAddr.add(block.getByteSize());
            chpeFixupBlocks.add(block);
        }
        return chpeFixupBlocks;
    }

    public static DataDirectory getDataDirectory(OptionalHeader optHeader, String dataDirectoryName, TaskMonitor monitor) throws IOException {
        var dataDirectories = optHeader.getDataDirectories();
        if (dataDirectories == null) {
            optHeader.processDataDirectories(monitor);
            dataDirectories = optHeader.getDataDirectories();
        }

        for (final var dataDirectory: dataDirectories) {
            if (dataDirectory == null) {
                continue;
            }
            if (dataDirectory.getDirectoryName().equals(dataDirectoryName)) {
                return dataDirectory;
            }
        }
        return null;
    }

    public static BaseRelocationDataDirectory getBaseRelocDataDirectory(OptionalHeader optHeader, TaskMonitor monitor) throws IOException {
        return (BaseRelocationDataDirectory) getDataDirectory(optHeader, "IMAGE_DIRECTORY_ENTRY_BASERELOC", monitor);
    }

    public static LoadConfigDataDirectory getLoadConfigDataDirectory(OptionalHeader optHeader, TaskMonitor monitor) throws IOException {
        return (LoadConfigDataDirectory) getDataDirectory(optHeader, "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", monitor);
    }

    private static long getDynamicValueRelocOffset(LoadConfigDirectory loadConfigDir) throws NoSuchFieldException, IllegalAccessException {
        var field = LoadConfigDirectory.class.getDeclaredField("dynamicValueRelocTableOffset");
        field.setAccessible(true);
        return field.getInt(loadConfigDir);
    }

    public static Address getChpeFixupBaseAddress(PortableExecutable peObj, Program program, TaskMonitor monitor) throws IOException, NoSuchFieldException, IllegalAccessException {
        var ntHeader = peObj.getNTHeader();
        var optHeader = ntHeader.getOptionalHeader();
        final var imageBase = optHeader.getImageBase();
        var baseReloc = getBaseRelocDataDirectory(optHeader, monitor);
        if (baseReloc == null) {
            System.err.println("Cannot find IMAGE_DIRECTORY_ENTRY_BASERELOC");
            return null;
        }

        final var loadConfigDataDir = getLoadConfigDataDirectory(optHeader, monitor);
        if (loadConfigDataDir == null) {
            System.err.println("Cannot find IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG");
            return null;
        }
        final var loadConfigDir = loadConfigDataDir.getLoadConfigDirectory();
        final var dynamicValueRelocOffset = getDynamicValueRelocOffset(loadConfigDir);

        return toAddr(program, imageBase + baseReloc.getVirtualAddress() + dynamicValueRelocOffset);
    }

    public static class Utils {
        public static byte[] shortToBytesArray(short i) {
            var byteArray = ByteBuffer.allocate(2).putInt(i).array();
            return new byte[]{
                    byteArray[1], byteArray[0]
            };
        }

        public static byte[] intToBytesArray(int i) {
            var byteArray = ByteBuffer.allocate(4).putInt(i).array();
            return new byte[] {
                    byteArray[3], byteArray[2], byteArray[1], byteArray[0]
            };
        }

        public static byte[] longToBytesArray(long i) {
            var byteArray = ByteBuffer.allocate(8).putLong(i).array();
            return new byte[] {
                    byteArray[7], byteArray[6], byteArray[5], byteArray[4],
                    byteArray[3], byteArray[2], byteArray[1], byteArray[0]
            };
        }
    }

    // NOTE: Used for loading data from json file
    public static class ChpeFixupEntryRaw {
        public int metaAndOffset;
        public long dataRaw;

        public ChpeFixupEntryRaw(int metaAndOffset, long dataRaw) {
            this.metaAndOffset = metaAndOffset;
            this.dataRaw = dataRaw;
        }

        @Override
        public String toString() {
            return String.format("metaAndOffset: %x\ndataRaw: %x\n",
                    metaAndOffset, dataRaw);
        }

        public int getByteSize() throws UnknownChpeFixupRelocTypeException {
            final var meta = (metaAndOffset & 0xf000) >> 12;
            final var relocType = ChpeFixupRelocType.decodeMetadata(meta);
            switch (relocType) {
                case ZERO_FILL:
                    return 2;
                case ASSIGN_VALUE:
                    return 2 + ChpeFixupRecord.decodeSizeMetadata(meta)[0];
                case DELTA:
                    return 2 + 2;
                default:
                    throw new UnknownChpeFixupRelocTypeException("Unknown CHPE fixup metadata 0b11");
            }
        }

        public Address exportToMemory(Memory memory, Address at) throws MemoryAccessException, UnknownChpeFixupRelocTypeException, BrokenChpeFixupRecord {
            memory.setShort(at, (short)(metaAndOffset & 0xffff));
            final var dataSize = getByteSize() - 2;
            switch (dataSize) {
                case 0:
                    return at.add(getByteSize());
                case 2:
                    memory.setShort(at.add(2), (short)(dataRaw & 0xffff));
                    return at.add(getByteSize());
                case 4:
                    memory.setInt(at.add(2), (int)(dataRaw & 0xffffffffL));
                    return at.add(getByteSize());
                case 8:
                    memory.setLong(at.add(2), dataRaw);
                    return at.add(getByteSize());
                default:
                    throw new BrokenChpeFixupRecord("CHPE fixup is invalid.");
            }
        }
    }

    // NOTE: Used for loading data from json file
    public static class ChpeFixupBlockRaw {
        public long baseOffset;
        public ChpeFixupEntryRaw[] records;

        public ChpeFixupBlockRaw(ChpeFixupBlock block) {
            this.baseOffset = block.baseOffset;
            this.records = new ChpeFixupEntryRaw[block.records.size()];
            for (int i = 0; i < block.records.size(); i++) {
                this.records[i] = block.records.get(i).getRawEntry();
            }
        }

        @Override
        public String toString() {
            return String.format("baseOffset: %x\n", baseOffset) + Arrays.toString(records);
        }

        public int getActualByteSize() throws UnknownChpeFixupRelocTypeException {
            int sizeOfChpeFixupEntries = 0;
            for (final var record: records) {
                sizeOfChpeFixupEntries += record.getByteSize();
            }
            return 4 + 4 + sizeOfChpeFixupEntries; // NOTE: 4 + 4 corresponds to the size of CHPE fixup block header
        }

        public int getByteSize() throws UnknownChpeFixupRelocTypeException {
            if (needsPadding()) {
                return getActualByteSize() + 2;
            } else {
                return getActualByteSize();
            }
        }

        public boolean needsPadding() throws UnknownChpeFixupRelocTypeException {
            return getActualByteSize() % 4 != 0;
        }

        public Address exportHeader(Memory memory, Address at) throws MemoryAccessException, UnknownChpeFixupRelocTypeException {
            memory.setInt(at, (int)(baseOffset & 0xffffffffL));
            at = at.add(4);
            memory.setInt(at, (int)(getByteSize() & 0xffffffffL));
            at = at.add(4);
            return at;
        }

        public Address exportRecords(Memory memory, Address at) throws BrokenChpeFixupRecord, UnknownChpeFixupRelocTypeException, MemoryAccessException {
            for (final var record: records) {
                at = record.exportToMemory(memory, at);
            }
            return at;
        }

        public Address exportToMemory(Memory memory, Address at) throws MemoryAccessException, UnknownChpeFixupRelocTypeException, BrokenChpeFixupRecord {
            at = exportHeader(memory, at);
            at = exportRecords(memory, at);
            if (needsPadding()) {
                memory.setShort(at, (short) 0);
                at = at.add(2);
            }
            return at;
        }
    }

    public static int calcByteSizeToBeConstructed(ChpeFixupBlockRaw[] blocks) throws UnknownChpeFixupRelocTypeException {
        int bytesToBeConstructed = 0;
        for (final var block: blocks) {
            bytesToBeConstructed += block.getByteSize();
        }
        return bytesToBeConstructed;
    }

    public static Optional<SectionHeader> findSectionHeaderContaining(PortableExecutable peObj, Address at, long imageBase) {
        final var atAsLong = at.getOffset();
        final var ntHeader = peObj.getNTHeader();
        final var fileHeader = ntHeader.getFileHeader();
        final var sectionHeaders = fileHeader.getSectionHeaders();
        for (final var sectionHeader: sectionHeaders) {
            final var beg = sectionHeader.getVirtualAddress() + imageBase;
            final var end = beg + sectionHeader.getVirtualSize();
            if (atAsLong >= beg && atAsLong < end) {
                return Optional.of(sectionHeader);
            }
        }
        return Optional.empty();
    }
}
