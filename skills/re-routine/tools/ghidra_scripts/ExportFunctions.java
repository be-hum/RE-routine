// 함수 목록과 문자열 참조를 TSV로 내보낸다. 인자: OUT_FUNCTIONS_TSV FILE_BASE
// 주소는 (Ghidra 주소 - (imageBase - FILE_BASE)) 로 objdump 기준 VA에 맞춘다.
// @category RE
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class ExportFunctions extends GhidraScript {
    private static String clean(String s) {
        return s.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        File out = new File(a[0]);
        long delta = currentProgram.getImageBase().getOffset() - Long.decode(a[1]);
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        Map<Function, List<String>> strs = new HashMap<>();

        try (PrintWriter sw = new PrintWriter(new FileWriter(new File(out.getParentFile(), "strings.tsv")))) {
            sw.println("addr\trefs\ttext");
            DataIterator it = currentProgram.getListing().getDefinedData(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Data d = it.next();
                if (!d.hasStringValue()) continue;
                String s = clean(String.valueOf(d.getValue()));
                Set<String> refs = new TreeSet<>();
                ReferenceIterator ri = rm.getReferencesTo(d.getAddress());
                while (ri.hasNext()) {
                    Function f = fm.getFunctionContaining(ri.next().getFromAddress());
                    if (f == null) continue;
                    refs.add(String.format("0x%x", f.getEntryPoint().getOffset() - delta));
                    strs.computeIfAbsent(f, k -> new ArrayList<>()).add(s);
                }
                sw.printf("0x%x\t%s\t%s%n", d.getAddress().getOffset() - delta, String.join(",", refs), s);
            }
        }

        try (PrintWriter w = new PrintWriter(new FileWriter(out))) {
            w.println("addr\tname\tsize\tcallers\tcallees\tstrings");
            FunctionIterator fi = fm.getFunctions(true);
            while (fi.hasNext() && !monitor.isCancelled()) {
                Function f = fi.next();
                if (f.isExternal() || f.isThunk()) continue;
                List<String> ss = strs.getOrDefault(f, Collections.emptyList());
                String joined = String.join(" | ", ss.subList(0, Math.min(3, ss.size())));
                w.printf("0x%x\t%s\t%d\t%d\t%d\t%s%n", f.getEntryPoint().getOffset() - delta, f.getName(),
                        f.getBody().getNumAddresses(), f.getCallingFunctions(monitor).size(),
                        f.getCalledFunctions(monitor).size(), joined);
            }
        }
    }
}
