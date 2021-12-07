// (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
// Apply CHPE fixup relocation entries
// @author Koh M. Nakagawa
// @category CHPEV2
// @keybinding
// @menupath
// @toolbar

import chpe.ChpeFixup;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.exporter.BinaryExporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.program.model.mem.Memory;

import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;

import java.io.IOException;
import java.util.List;
import java.io.File;

public class ApplyChpeFixup extends GhidraScript {

    private void applyAllChpeFixups(List<ChpeFixup.ChpeFixupBlock> chpeFixupBlocks, Memory memory, long imageBase) throws MemoryAccessException, ChpeFixup.BrokenChpeFixupRecord {
        printerr("This script changes the contents of 1. PE header 2. code in text section 3. some data section");
        var assembler = Assemblers.getAssembler(currentProgram);
        for (final var chpeFixupBlock: chpeFixupBlocks) {
            final var baseOffset = chpeFixupBlock.baseOffset;
            for (final var chpeFixupRecord: chpeFixupBlock.records) {
                final var addrToBeRelocated = toAddr(chpeFixupRecord.offset + baseOffset + imageBase);
                chpeFixupRecord.applyFixup(memory, addrToBeRelocated, assembler);
            }
        }
    }

    private void exportCurrentProgram() throws IOException, ExporterException, CancelledException {
        var dir = askDirectory("Please choose a directory to export this modified binary", "Select");
        var fout = new File(dir, currentProgram.getName() + ".x64");
        var exporter = new BinaryExporter();
        exporter.export(fout, currentProgram, currentProgram.getMemory(), getMonitor());
        popup("Relocation applied binary is exported to " + fout.getAbsolutePath() + ".");
    }

    public void run() throws Exception {
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
            printerr("Is this file really a PE file?");
            return;
        }

        final var chpeFixupBlocks = ChpeFixup.getChpeFixupBlocks(peObj, currentProgram, getMonitor());
        applyAllChpeFixups(chpeFixupBlocks, currentProgram.getMemory(), currentProgram.getImageBase().getOffset());
        exportCurrentProgram();
    }
}
