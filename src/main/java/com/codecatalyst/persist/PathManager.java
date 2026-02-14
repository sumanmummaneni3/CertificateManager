package com.codecatalyst.persist;


import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static com.codecatalyst.common.CertConstants.DATA_FOLDER_NAME;

public class PathManager {
    public static Path getAppHome() {
        // Resolves to /Users/suman/.certmgr on Mac/Linux
        // and C:\Users\Suman\.certmgr on Windows
        String userHome = System.getProperty("user.home");
        Path appHome = Paths.get(userHome, DATA_FOLDER_NAME);

        try {
            if (!Files.exists(appHome)) {
                Files.createDirectories(appHome);
            }
        } catch (IOException e) {
            System.err.println("Critical Error: Could not create app directory " + appHome);
        }
        return appHome;
    }
}
