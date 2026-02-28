package com.shieldrasp;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import com.shieldrasp.hooks.ProcessBuilderHook;
import com.shieldrasp.hooks.JdbcHook;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

public class ShieldRaspTransformer implements ClassFileTransformer {
    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        
        try {
            if (className.equals("java/lang/ProcessBuilder")) {
                ClassReader cr = new ClassReader(classfileBuffer);
                ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
                cr.accept(new ProcessBuilderHook(Opcodes.ASM9, cw), ClassReader.EXPAND_FRAMES);
                return cw.toByteArray();
            }
            if (className.equals("java/sql/Statement")) {
                ClassReader cr = new ClassReader(classfileBuffer);
                ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
                cr.accept(new JdbcHook(Opcodes.ASM9, cw), ClassReader.EXPAND_FRAMES);
                return cw.toByteArray();
            }
        } catch (Throwable t) {
            // Fail open: return original bytecode if transformation fails
            t.printStackTrace();
        }
        return null;
    }
}
