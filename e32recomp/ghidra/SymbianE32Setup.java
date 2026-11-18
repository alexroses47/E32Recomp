// Prepares a raw Symbian E32Image code section for analysis: maps .data/.bss,
// names every import stub from imports.tsv and resolves data imports (typeinfo/vtables)
// to labelled slots in a synthetic IMPORTS block.
// Run as -preScript, after importing code.bin with BinaryLoader at iCodeBase.
// Args: imports.tsv data.bin dataBase bssSize
//@category Symbian

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.label.DemanglerCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class SymbianE32Setup extends GhidraScript {

    private static final long IMPORTS_BASE = 0x10000000L;

    private void demangle(Address addr, String sym) {
        if (sym.startsWith("_Z")) {
            // Names only: the demangled signature omits the implicit `this`, which hides arguments.
            DemanglerOptions opts = new DemanglerOptions();
            opts.setApplySignature(false);
            new DemanglerCmd(addr, sym, opts).applyTo(currentProgram, monitor);
        }
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4) {
            throw new IllegalArgumentException("args: imports.tsv data.bin dataBase bssSize");
        }
        File tsv = new File(args[0]);
        File data = new File(args[1]);
        long dataBase = Long.decode(args[2]);
        long bssSize = Long.decode(args[3]);
        Memory mem = currentProgram.getMemory();

        // Code block came from BinaryLoader: make it executable code.
        for (MemoryBlock b : mem.getBlocks()) {
            b.setName(".text");
            b.setExecute(true);
            b.setWrite(false);
        }

        // .data and .bss at their link address (no relocation needed).
        Address dataAddr = toAddr(dataBase);
        try (FileInputStream in = new FileInputStream(data)) {
            MemoryBlock db = mem.createInitializedBlock(".data", dataAddr, in, data.length(), monitor, false);
            db.setRead(true);
            db.setWrite(true);
        }
        if (bssSize > 0) {
            MemoryBlock bb = mem.createUninitializedBlock(".bss", dataAddr.add(data.length()), bssSize, false);
            bb.setRead(true);
            bb.setWrite(true);
        }

        List<String[]> rows = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new FileReader(tsv))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (!line.isBlank()) rows.add(line.split("\t"));
            }
        }

        // One 4-byte slot per import stands in for the symbol's address in its DLL.
        MemoryBlock ib = mem.createInitializedBlock("IMPORTS", toAddr(IMPORTS_BASE), rows.size() * 4L, (byte) 0, monitor, false);
        ib.setRead(true);

        int funcs = 0, datas = 0;
        for (int i = 0; i < rows.size(); i++) {
            String kind = rows.get(i)[0];
            Address entry = toAddr(Long.decode(rows.get(i)[1]));
            String dll = rows.get(i)[2];
            String ordinal = rows.get(i)[3];
            String sym = rows.get(i)[4];
            Address slot = toAddr(IMPORTS_BASE + 4L * i);

            int word = getInt(entry);
            int addend = (word >>> 16) & 0xFFFF;   // ELF-derived import: ordinal | addend << 16
            String origin = dll + ".dll @" + ordinal;

            if (kind.equals("func")) {
                // ldr pc,[pc,#-4] ; .word <import>  -> stub is the callable function
                Address stub = entry.subtract(4);
                createLabel(slot, "__imp_" + sym, true, SourceType.IMPORTED);
                setInt(entry, (int) slot.getOffset());
                disassemble(stub);
                Function f = getFunctionAt(stub);
                if (f == null) f = createFunction(stub, null);
                // IMPORTED (not USER_DEFINED) so the GNU demangler is allowed to rename it.
                f.setName(sym, SourceType.IMPORTED);
                demangle(stub, sym);
                setPlateComment(stub, "import " + origin);
                funcs++;
            } else {
                createLabel(slot, sym, true, SourceType.IMPORTED);
                demangle(slot, sym);
                setInt(entry, (int) (slot.getOffset() + addend));
                setEOLComment(entry, "import " + origin + (addend != 0 ? " +" + addend : ""));
                datas++;
            }
            clearListing(entry);
            createData(entry, PointerDataType.dataType);
        }

        addEntryPoint(currentProgram.getImageBase());
        createFunction(currentProgram.getImageBase(), "_E32Startup");
        println("SymbianE32Setup: " + funcs + " import stubs, " + datas + " data imports labelled");
    }
}
