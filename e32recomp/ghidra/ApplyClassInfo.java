// Applies class information recovered offline to the program:
//  - rtti.tsv / vtables.tsv (tools/rtti_scan.py): class namespaces, typeinfo and
//    vtable labels, virtual methods named Owner::vNN (Owner = class that
//    introduces/overrides the slot); slots 0/1 of lang::Object descendants are
//    the complete and deleting destructors.
//  - ka3d_strings.tsv (tools/ka3d_strings.py): functions that reference a
//    distinctive KA3D source literal get the KA3D function name.
// Only functions with default (FUN_) names or names set by this script are renamed.
// Run as -postScript. Args: rtti.tsv vtables.tsv ka3d_strings.tsv
//@category Symbian

import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;

public class ApplyClassInfo extends GhidraScript {

    private final Set<Address> namedHere = new HashSet<>();
    private final Map<String, Namespace> nsCache = new HashMap<>();
    private int created = 0, renamedVirt = 0, sharedVirt = 0, renamedKa3d = 0;

    private List<String[]> readTsv(String path) throws Exception {
        List<String[]> rows = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new FileReader(path))) {
            String line = r.readLine(); // header
            while ((line = r.readLine()) != null) {
                if (!line.isBlank()) rows.add(line.split("\t", -1));
            }
        }
        return rows;
    }

    /** Split "a::b<c::d>::e" on top-level "::" only. */
    private static List<String> splitScope(String name) {
        List<String> parts = new ArrayList<>();
        int depth = 0, start = 0;
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c == '<') depth++;
            else if (c == '>') depth--;
            else if (depth == 0 && c == ':' && i + 1 < name.length() && name.charAt(i + 1) == ':') {
                parts.add(name.substring(start, i));
                start = i + 2;
                i++;
            }
        }
        parts.add(name.substring(start));
        return parts;
    }

    private static String clean(String s) {
        return SymbolUtilities.replaceInvalidChars(s, true);
    }

    /** Namespace for a C++ scope; the last component becomes a class when asClass. */
    private Namespace scope(String full, boolean asClass) throws Exception {
        if (full == null || full.isEmpty()) return currentProgram.getGlobalNamespace();
        String key = full + (asClass ? "#c" : "");
        Namespace cached = nsCache.get(key);
        if (cached != null) return cached;
        SymbolTable st = currentProgram.getSymbolTable();
        Namespace ns = currentProgram.getGlobalNamespace();
        List<String> parts = splitScope(full);
        for (int i = 0; i < parts.size(); i++) {
            String p = clean(parts.get(i));
            Namespace next = st.getNamespace(p, ns);
            boolean last = i == parts.size() - 1;
            if (next == null) {
                next = (last && asClass) ? st.createClass(ns, p, SourceType.ANALYSIS)
                                         : st.createNameSpace(ns, p, SourceType.ANALYSIS);
            } else if (last && asClass && !(next instanceof ghidra.program.model.listing.GhidraClass)) {
                next = st.convertNamespaceToClass(next);
            }
            ns = next;
        }
        nsCache.put(key, ns);
        return ns;
    }

    private void label(long addr, String cls, String name) throws Exception {
        Address a = toAddr(addr);
        Symbol s = currentProgram.getSymbolTable().createLabel(a, clean(name), scope(cls, true), SourceType.ANALYSIS);
        s.setPrimary();
    }

    private Function functionAt(long target) throws Exception {
        boolean thumb = (target & 1) != 0;
        Address a = toAddr(target & ~1L);
        Function f = getFunctionAt(a);
        if (f != null) return f;
        if (getInstructionAt(a) == null) {
            Register tmode = currentProgram.getRegister("TMode");
            if (tmode != null) {
                currentProgram.getProgramContext().setValue(tmode, a, a, thumb ? BigInteger.ONE : BigInteger.ZERO);
            }
            disassemble(a);
        }
        f = createFunction(a, null);
        if (f != null) created++;
        return f;
    }

    private boolean renamable(Function f) {
        return f.getSymbol().getSource() == SourceType.DEFAULT || namedHere.contains(f.getEntryPoint());
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("args: rtti.tsv vtables.tsv ka3d_strings.tsv");

        // ---- classes, typeinfo, vtable labels
        Map<String, String> baseOf = new HashMap<>();
        for (String[] r : readTsv(args[0])) {
            long ti = Long.decode(r[0]);
            String cls = r[2];
            scope(cls, true);
            label(ti, cls, "typeinfo");
            String b = r[3].isEmpty() ? null : r[3].split(",")[0];
            if (b != null) baseOf.put(cls, b);
            if (!r[4].equals("-")) label(Long.decode(r[4]), cls, "vtable");
        }
        Set<String> objectKids = new HashSet<>();
        for (String c : baseOf.keySet()) {
            for (String p = baseOf.get(c); p != null; p = baseOf.get(p)) {
                if (p.equals("lang::Object")) { objectKids.add(c); break; }
            }
        }
        objectKids.add("lang::Object");

        // ---- virtual slots
        Map<Address, String> firstName = new HashMap<>();
        Set<String> secondaryLabelled = new HashSet<>();
        for (String[] r : readTsv(args[1])) {
            long vt = Long.decode(r[0]);
            String cls = r[1];
            int ott = Integer.parseInt(r[2]);
            int slot = Integer.parseInt(r[3]);
            long target = Long.decode(r[4]);
            String owner = r[5];
            Address slotAddr = toAddr(vt + 8 + 4L * slot);
            try {
                if (getDataAt(slotAddr) == null) {
                    clearListing(slotAddr, slotAddr.add(3));
                    createData(slotAddr, PointerDataType.dataType);
                }
            } catch (CodeUnitInsertionException e) { /* overlapping data: leave it */ }
            if (ott != 0) {
                if (secondaryLabelled.add(cls + vt)) label(vt, cls, "vtable_" + (-ott));
                continue; // thunks for secondary bases: not renamed
            }
            Function f = functionAt(target);
            if (f == null) continue;
            String name;
            if (objectKids.contains(owner) && slot <= 1) {
                List<String> p = splitScope(owner);
                String simple = p.get(p.size() - 1).replaceAll("<.*", "");
                name = "~" + simple + (slot == 1 ? "_deleting" : "");
            } else {
                name = String.format("v%02d", slot);
            }
            String full = owner + "::" + name;
            String prev = firstName.putIfAbsent(f.getEntryPoint(), full);
            if (prev != null && !prev.equals(full)) {
                // same body reused by unrelated classes (identical code folding)
                String c = f.getComment();
                if (c == null || !c.contains(full)) {
                    f.setComment((c == null ? "" : c + "\n") + "also " + full);
                }
                sharedVirt++;
                continue;
            }
            if (prev == null && renamable(f)) {
                f.setParentNamespace(scope(owner, true));
                f.setName(clean(name), SourceType.ANALYSIS);
                namedHere.add(f.getEntryPoint());
                renamedVirt++;
            }
        }

        // ---- KA3D literals -> functions
        Map<String, Set<String>> litOwners = new HashMap<>();
        List<String[]> lits = readTsv(args[2]);
        for (String[] r : lits) {
            litOwners.computeIfAbsent(r[0], k -> new HashSet<>()).add(r[1] + "|" + r[2]);
        }
        Map<String, Map<Function, Integer>> votes = new TreeMap<>();
        ReferenceManager rm = currentProgram.getReferenceManager();
        for (String[] r : lits) {
            String file = r[1], func = r[2], lit = r[3];
            if (func.equals("-") || lit.length() < 10 || litOwners.get(r[0]).size() != 1) continue;
            if (file.contains("/dx/") || file.contains("/win32/") || file.contains("/ode/")) continue;
            String[] dirs = file.split("/");
            String full = dirs.length >= 3 ? dirs[1] + "::" + func : func; // source/<ns>/File.cpp
            Address s = toAddr(Long.decode(r[0]));
            Set<Function> users = new HashSet<>();
            for (Reference ref : rm.getReferencesTo(s)) {
                Address from = ref.getFromAddress();
                Function f = getFunctionContaining(from);
                if (f != null) { users.add(f); continue; }
                for (Reference ref2 : rm.getReferencesTo(from)) { // literal pool word
                    Function g = getFunctionContaining(ref2.getFromAddress());
                    if (g != null) users.add(g);
                }
            }
            for (Function f : users) {
                votes.computeIfAbsent(full, k -> new HashMap<>()).merge(f, 1, Integer::sum);
            }
        }
        StringBuilder rep = new StringBuilder();
        for (Map.Entry<String, Map<Function, Integer>> e : votes.entrySet()) {
            String full = e.getKey();
            List<Map.Entry<Function, Integer>> cand = new ArrayList<>(e.getValue().entrySet());
            cand.sort((x, y) -> y.getValue() - x.getValue());
            Function best = cand.get(0).getKey();
            boolean unique = cand.size() == 1 || cand.get(0).getValue() > cand.get(1).getValue();
            for (Map.Entry<Function, Integer> c : cand) {
                Function f = c.getKey();
                if (f == best && unique && renamable(f)) {
                    String old = f.getName(true);
                    List<String> p = splitScope(full);
                    String simple = p.remove(p.size() - 1);
                    f.setParentNamespace(scope(String.join("::", p), p.size() > 1));
                    f.setName(clean(simple), SourceType.ANALYSIS);
                    if (namedHere.contains(f.getEntryPoint())) f.setComment("vtable slot: " + old);
                    namedHere.add(f.getEntryPoint());
                    renamedKa3d++;
                    rep.append(String.format("%s\t%s\t%d\n", f.getEntryPoint(), full, c.getValue()));
                } else {
                    String cm = f.getComment();
                    String note = "uses strings of ka3d " + full;
                    if (cm == null || !cm.contains(note)) f.setComment((cm == null ? "" : cm + "\n") + note);
                }
            }
        }
        println("ka3d names:\n" + rep);

        int total = 0, named = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            total++;
            if (f.getSymbol().getSource() != SourceType.DEFAULT) named++;
        }
        println(String.format("ApplyClassInfo: %d new functions, %d virtuals named (%d shared bodies), "
                + "%d ka3d functions named; functions %d, with name %d", created, renamedVirt, sharedVirt,
                renamedKa3d, total, named));
    }
}
