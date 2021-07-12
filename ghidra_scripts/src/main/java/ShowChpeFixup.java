// (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
// Show CHPE fixup relocation entries
// @author Koh M. Nakagawa
// @category CHPEV2
// @keybinding
// @menupath
// @toolbar

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.tablechooser.*;
import ghidra.program.model.address.Address;

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import chpe.ChpeFixup;

public class ShowChpeFixup extends GhidraScript {

    private static class ChpeFixupRecordsTableElem implements AddressableRowObject {

        public Address location;
        public Optional<Long> dataBeWritten;
        public int metaAndOffset;
        public int dataSize;
        public Address relocEntryLocation;
        public ChpeFixup.ChpeFixupRelocType type;

        ChpeFixupRecordsTableElem(Address location_,
                                  Optional<Long> dataBeWritten_,
                                  int metaAndOffset_,
                                  int dataSize_,
                                  Address relocEntryLocation_,
                                  ChpeFixup.ChpeFixupRelocType type_) {
            location = location_;
            dataBeWritten = dataBeWritten_;
            metaAndOffset = metaAndOffset_;
            relocEntryLocation = relocEntryLocation_;
            dataSize = dataSize_;
            type = type_;
        }

        @Override
        public Address getAddress() {
            return location;
        }
    }

    private static class DataBeWrittenColumn extends StringColumnDisplay {

        @Override
        public String getColumnValue(AddressableRowObject addressableRowObject) {
            final var elem = (ChpeFixupRecordsTableElem)addressableRowObject;
            if (elem.dataBeWritten.isPresent()) {
                if (elem.dataSize == 2) {
                    return Integer.toUnsignedString(elem.dataBeWritten.get().intValue(), 16);
                } else if (elem.dataSize == 4) {
                    return Integer.toUnsignedString(elem.dataBeWritten.get().intValue(), 16);
                } else if (elem.dataSize == 8) {
                    return Long.toUnsignedString(elem.dataBeWritten.get(), 16);
                } else {
                    return "Error! This value should be power of 2.";
                }
            } else {
                return "None";
            }
        }

        @Override
        public String getColumnName() {
            return "Data be written";
        }
    }

    private static class MetadataAndOffsetColumn extends StringColumnDisplay {
        @Override
        public String getColumnValue(AddressableRowObject addressableRowObject) {
            final var elem = (ChpeFixupRecordsTableElem)addressableRowObject;
            return Long.toHexString(elem.metaAndOffset);
        }

        @Override
        public String getColumnName() {
            return "Metadata and Offset";
        }
    }

    private static class RelocEntryLocation extends AbstractColumnDisplay<Address> {
        @Override
        public Address getColumnValue(AddressableRowObject addressableRowObject) {
            final var elem = (ChpeFixupRecordsTableElem)addressableRowObject;
            return elem.relocEntryLocation;
        }

        @Override
        public String getColumnName() {
            return "Relocation Entry Location";
        }

        @Override
        public int compare(AddressableRowObject o1, AddressableRowObject o2) {
            final var o1Elem = (ChpeFixupRecordsTableElem)o1;
            final var o2Elem = (ChpeFixupRecordsTableElem)o2;
            return o1Elem.relocEntryLocation.compareTo(o2Elem.relocEntryLocation);
        }
    }

    private static class RelocEntryType extends StringColumnDisplay {
        @Override
        public String getColumnValue(AddressableRowObject addressableRowObject) {
            final var elem = (ChpeFixupRecordsTableElem)addressableRowObject;
            return elem.type.toString();
        }

        @Override
        public String getColumnName() {
            return "Relocation Type";
        }
    }

    private void configureTableColumns(TableChooserDialog tableDialog) {
        tableDialog.addCustomColumn(new DataBeWrittenColumn());
        tableDialog.addCustomColumn(new MetadataAndOffsetColumn());
        tableDialog.addCustomColumn(new RelocEntryLocation());
        tableDialog.addCustomColumn(new RelocEntryType());
    }

    private void showAsTable(List<ChpeFixup.ChpeFixupBlock> chpeFixupBlocks, TableChooserDialog tableDialog, long imageBase) {
        for (final var chpeFixupBlock: chpeFixupBlocks) {
            final var baseOffset = chpeFixupBlock.baseOffset;
            for (final var chpeFixupRecord: chpeFixupBlock.records) {
                final var pointToBeRelocated = toAddr(chpeFixupRecord.offset + baseOffset + imageBase);
                tableDialog.add(
                    new ChpeFixupRecordsTableElem(
                        pointToBeRelocated,
                        chpeFixupRecord.data(),
                        chpeFixupRecord.metaAndOffset,
                        chpeFixupRecord.sizeToBeWritten,
                        chpeFixupRecord.location,
                        chpeFixupRecord.relocType
                    )
                );
            }
        }
    }

    public void run() throws Exception {
        var tableDialog = createTableChooserDialog(
                "Show ChpeFixup records of " + currentProgram.getName(),
                null);
        configureTableColumns(tableDialog);
        tableDialog.show();

        var provider = new MemoryByteProvider(
            currentProgram.getMemory(), currentProgram.getImageBase()
        );

        PortableExecutable peObj;
        try {
            peObj = PortableExecutable.createPortableExecutable(
                    RethrowContinuesFactory.INSTANCE,
                    provider,
                    PortableExecutable.SectionLayout.MEMORY,
                    false,
                    false
                );
        } catch (Exception e) {
            printerr(e.toString());
            printerr("Is this file really PE file?");
            return;
        }

        var chpeFixupBlocks = ChpeFixup.getChpeFixupBlocks(peObj, currentProgram, getMonitor());
        showAsTable(chpeFixupBlocks, tableDialog, currentProgram.getImageBase().getOffset());

        final var exportJson = askYesNo("JSON export", "Would you like to export relocation entries as JSON file?");
        if (exportJson) {
            final var dir = askDirectory("Please choose a directory to export this modified binary", "Select");
            final var jsonOut = new File(dir, "chpe_fixup.json");

            var rawBlocks = new ArrayList<ChpeFixup.ChpeFixupBlockRaw>();
            for (final var chpeFixupBlock : chpeFixupBlocks) {
                rawBlocks.add(new ChpeFixup.ChpeFixupBlockRaw(chpeFixupBlock));
            }

            var gson = new GsonBuilder().setPrettyPrinting().create();
            var writer = new FileWriter(jsonOut);
            gson.toJson(rawBlocks.toArray(), writer);
            writer.close();

            popup("Relocation entries are exported to " + jsonOut.toString() + ".");
        }
    }
}
