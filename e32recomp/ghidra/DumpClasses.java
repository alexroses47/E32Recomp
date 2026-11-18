// Writes the decompiled C of every function in the given class namespaces (plus the
// unnamed functions they call, one level deep) to <outdir>/<Class>.c — for reading only.
// Args: outdir Class1|@0xADDR [...]
//@category Symbian

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class DumpClasses extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        File out = new File(args[0]);
        out.mkdirs();
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        Set<Function> done = new HashSet<>();
        for (int a = 1; a < args.length; a++) {
            String cls = args[a];
            List<Function> fs = new ArrayList<>();
            if (cls.startsWith("@")) {   // @0xADDR: the function containing that address
                ghidra.program.model.address.Address at = toAddr(Long.decode(cls.substring(1)));
                Function f = getFunctionContaining(at);
                if (f != null) fs.add(f);
                else {   // literal-pool word: take the functions that load it
                    for (ghidra.program.model.symbol.Reference r : getReferencesTo(at)) {
                        Function g = getFunctionContaining(r.getFromAddress());
                        if (g != null && !fs.contains(g)) fs.add(g);
                    }
                }
                cls = "at_" + cls.substring(1);
            } else {
                for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                    if (f.getParentNamespace().getName(true).equals(cls)) fs.add(f);
                }
            }
            List<Function> extra = new ArrayList<>();
            for (Function f : fs) {
                for (Function c : f.getCalledFunctions(monitor)) {
                    if (c.getSymbol().getSource() == SourceType.DEFAULT && !fs.contains(c) && !extra.contains(c)) extra.add(c);
                }
            }
            fs.addAll(extra);
            try (PrintWriter w = new PrintWriter(new File(out, cls.replace("::", "_") + ".c"))) {
                for (Function f : fs) {
                    if (!done.add(f)) { w.println("// " + f.getName(true) + " @ " + f.getEntryPoint() + " (see other file)\n"); continue; }
                    DecompileResults r = d.decompileFunction(f, 120, monitor);
                    w.println("// ===== " + f.getName(true) + " @ " + f.getEntryPoint() + " (" + f.getBody().getNumAddresses() + " bytes)");
                    w.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// decompile failed: " + r.getErrorMessage());
                }
            }
            println(cls + ": " + fs.size() + " functions");
        }
    }
}
