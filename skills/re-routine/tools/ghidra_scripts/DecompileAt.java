// 지정 주소를 포함하는 함수만 디컴파일한다. 인자: OUT_FILE FILE_BASE ADDR [ADDR...]
// ADDR은 objdump 기준 VA (0x 접두어 허용).
// @category RE
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.*;

public class DecompileAt extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        File out = new File(a[0]);
        long delta = currentProgram.getImageBase().getOffset() - Long.decode(a[1]);
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        try (PrintWriter w = new PrintWriter(new FileWriter(out))) {
            for (int i = 2; i < a.length; i++) {
                long va;
                try {
                    String h = a[i].toLowerCase().startsWith("0x") ? a[i].substring(2) : a[i];
                    va = Long.parseUnsignedLong(h, 16);   // objdump 표기(0x 없음, 0 채움)도 16진수로 해석
                } catch (NumberFormatException e) {
                    w.printf("// %s: 주소 형식 오류 (16진수 VA)%n", a[i]); continue;
                }
                Function f = getFunctionContaining(toAddr(va + delta));
                if (f == null) { w.printf("// %s: 함수 없음%n", a[i]); continue; }
                w.printf("// function %s @ 0x%x%n", f.getName(), f.getEntryPoint().getOffset() - delta);
                DecompileResults r = ifc.decompileFunction(f, 60, monitor);
                if (!r.decompileCompleted()) { w.println("// 디컴파일 실패: " + r.getErrorMessage()); continue; }
                w.println(r.getDecompiledFunction().getC());
            }
        } finally {
            ifc.dispose();
        }
    }
}
