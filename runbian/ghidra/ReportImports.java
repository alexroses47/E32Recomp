// Prints analysis stats and the most-called import stubs (with demangled names),
// then decompiles one caller of a given import as a sanity check.
// Args: [importNameSubstring]
//@category Symbian

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class ReportImports extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String needle = getScriptArgs().length > 0 ? getScriptArgs()[0] : "DrawNow";
        int total = currentProgram.getFunctionManager().getFunctionCount();
        List<Function> stubs = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            String c = getPlateComment(f.getEntryPoint());
            if (c != null && c.startsWith("import ")) stubs.add(f);
        }
        println("functions: " + total + ", import stubs: " + stubs.size());
        stubs.sort((a, b) -> refs(b) - refs(a));
        for (int i = 0; i < Math.min(15, stubs.size()); i++) {
            Function f = stubs.get(i);
            println(String.format("  %4d calls  %s  [%s]", refs(f), f.getName(true),
                getPlateComment(f.getEntryPoint())));
        }
        for (Function f : stubs) {
            if (!f.getName(true).contains(needle)) continue;
            for (Reference r : getReferencesTo(f.getEntryPoint())) {
                Function caller = getFunctionContaining(r.getFromAddress());
                if (caller == null) continue;
                DecompInterface di = new DecompInterface();
                di.openProgram(currentProgram);
                DecompileResults res = di.decompileFunction(caller, 60, monitor);
                println("---- decompiled caller of " + f.getName(true) + ": " + caller.getName() + " @ " + caller.getEntryPoint());
                println(res.getDecompiledFunction() != null ? res.getDecompiledFunction().getC() : res.getErrorMessage());
                di.dispose();
                return;
            }
        }
    }

    private int refs(Function f) {
        return getReferencesTo(f.getEntryPoint()).length;
    }
}
