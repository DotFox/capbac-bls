package dev.dotfox.bls.impl.blst;

import java.lang.reflect.InvocationTargetException;
import java.util.Optional;

import dev.dotfox.bls.impl.BLS12381;

public class BlstLoader {
    private static final String LIBRARY_NAME = System.mapLibraryName("blst");
    private static final String OS_NAME = System.getProperty("os.name").replaceFirst(" .*", "");

    public static final Optional<BLS12381> INSTANCE = loadBlst();

    private static Optional<BLS12381> loadBlst() {
        try {
            if (optimisedLibrarySupported()) {
                useOptimisedBlstLibrary();
            }

            Class.forName("supranational.blst.blstJNI");

            final Class<?> blstClass = Class.forName("dev.dotfox.bls.impl.blst.BlstBLS12381");
            return Optional.of((BLS12381) blstClass.getDeclaredConstructor().newInstance());
        } catch (final InstantiationException
                 | ExceptionInInitializerError
                 | InvocationTargetException
                 | NoSuchMethodException
                 | IllegalAccessException
                 | ClassNotFoundException e) {
            return Optional.empty();
        }
    }

    private static void useOptimisedBlstLibrary() {
        final String optimisedResource =
            OS_NAME + "/optimised" + "/" + System.getProperty("os.arch") + "/" + LIBRARY_NAME;
        System.setProperty("supranational.blst.jniResource", optimisedResource);
    }

    private static boolean optimisedLibrarySupported() {
        try {
            switch (OS_NAME) {
            case "Linux":
                return LinuxCpuInfo.supportsOptimisedBlst();
            case "Mac":
                return MacCpuInfo.supportsOptimisedBlst();
            default:
                return false;
            }
        } catch (final Throwable t) {
            return false;
        }
    }
}
