public class BufferOverflowVulnerableClass {

    public void triggerOverflow() {
        int[] source = new int[10];
        int[] dest = new int[5];

        for (int i = 0; i < source.length; i++) {
            source[i] = i;
        }

        // This call uses a method name that includes "copy" and attempts an unsafe copy.
        copyBuffer(source, dest, 0, 10);
    }

    private void copyBuffer(int[] src, int[] dst, int start, int count) {
        for (int i = start; i < start + count; i++) {
            dst[i] = src[i];
        }
    }
}
