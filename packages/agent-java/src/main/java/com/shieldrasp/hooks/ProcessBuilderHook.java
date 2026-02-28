package com.shieldrasp.hooks;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

public class ProcessBuilderHook extends ClassVisitor {
    public ProcessBuilderHook(int api, ClassVisitor classVisitor) {
        super(api, classVisitor);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
        if (name.equals("start") && descriptor.equals("()Ljava/lang/Process;")) {
            return new MethodVisitor(api, mv) {
                @Override
                public void visitCode() {
                    // Inject: com.shieldrasp.detection.CmdDetector.detect(this.command);
                    mv.visitVarInsn(Opcodes.ALOAD, 0);
                    mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/ProcessBuilder", "command", "()Ljava/util/List;", false);
                    mv.visitMethodInsn(Opcodes.INVOKESTATIC, "com/shieldrasp/detection/CmdDetector", "detect", "(Ljava/util/List;)V", false);
                    super.visitCode();
                }
            };
        }
        return mv;
    }
}
