package jp.co.jri.analyzer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.*;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.eclipse.jgit.lib.ProgressMonitor;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;

import java.io.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import java.util.concurrent.atomic.AtomicInteger;

public class GitHubMavenAnalyzer {
    // UPDATE: Register JavaTimeModule with ObjectMapper
    private static final ObjectMapper mapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())  // ADD THIS LINE
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS) // Optional: makes dates human-readable
            .enable(SerializationFeature.INDENT_OUTPUT);

    private final String tempDir;

    public record AnalysisConfig(
            boolean includeTestCode,
            boolean analyzeDependencies,
            boolean detailedMethodAnalysis,
            List<String> excludePatterns,
            int maxFileSize
    ) {
        public AnalysisConfig {
            if (excludePatterns == null) {
                excludePatterns = List.of(
                        ".*/target/.*",
                        ".*/build/.*",
                        ".*/\\.git/.*",
                        ".*/node_modules/.*"
                );
            }
        }

        public static AnalysisConfig defaults() {
            return new AnalysisConfig(
                    true,
                    true,
                    true,
                    null,
                    10 * 1024 * 1024
            );
        }
    }

    public GitHubMavenAnalyzer() throws IOException {
        this.tempDir = Files.createTempDirectory("github-maven-analysis").toString();
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("""
                Usage: java GitHubMavenAnalyzer <github-repo-url> [output-file]
                Example: java GitHubMavenAnalyzer https://github.com/spring-projects/spring-boot.git analysis.json
                
                For private repositories:
                java GitHubMavenAnalyzer <repo-url> <output-file> <username> <token>
                """);
            return;
        }

        String repoUrl = args[0];
        String outputFile = args.length > 1 ? args[1] : "maven-project-analysis.json";
        String username = args.length > 2 ? args[2] : null;
        String token = args.length > 3 ? args[3] : null;

        try {
            GitHubMavenAnalyzer analyzer = new GitHubMavenAnalyzer();
            Map<String, Object> analysis = analyzer.analyzeRepository(repoUrl, username, token);

            mapper.writeValue(new File(outputFile), analysis);
            System.out.println("Analysis saved to: " + outputFile);

            analyzer.printSummary(analysis);

        } catch (Exception e) {
            System.err.println("Analysis failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public Map<String, Object> analyzeRepository(String repoUrl) throws Exception {
        return analyzeRepository(repoUrl, null, null);
    }

    public Map<String, Object> analyzeRepository(String repoUrl, String username, String token) throws Exception {
        return analyzeRepository(repoUrl, username, token, AnalysisConfig.defaults());
    }

    public Map<String, Object> analyzeRepository(String repoUrl, String username, String token,
                                                 AnalysisConfig config) throws Exception {
        System.out.println("Analyzing repository: " + repoUrl);

        String repoName = extractRepoName(repoUrl);
        String localRepoPath = Paths.get(tempDir, repoName).toString();

        cloneRepository(repoUrl, localRepoPath, username, token);

        Map<String, Object> analysis = new HashMap<>();
        analysis.put("repositoryUrl", repoUrl);
        analysis.put("analysisDate", Instant.now());
        analysis.put("localPath", localRepoPath);
        analysis.put("config", Map.of(
                "includeTestCode", config.includeTestCode(),
                "analyzeDependencies", config.analyzeDependencies(),
                "detailedMethodAnalysis", config.detailedMethodAnalysis()
        ));

        List<Map<String, Object>> mavenProjects = findAndAnalyzeMavenProjects(localRepoPath, config);
        analysis.put("mavenProjects", mavenProjects);

        analysis.put("overallStatistics", generateOverallStatistics(mavenProjects));

        return analysis;
    }

    // Helper methods for safe data extraction
    private long getLongValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof Number number) {
            return number.longValue();
        }
        return 0L;
    }

    private List<?> getListValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof List<?> list) {
            return list;
        }
        return List.of();
    }

    private String getStringValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value instanceof String string) {
            return string;
        }
        return "";
    }

    private boolean shouldIncludeFile(Path path, AnalysisConfig config) {
        String pathStr = path.toString();
        return config.excludePatterns().stream()
                .noneMatch(pattern -> pathStr.matches(pattern));
    }

    private List<Map<String, Object>> findAndAnalyzeMavenProjects(String projectRoot, AnalysisConfig config) throws Exception {
        List<Map<String, Object>> projects = new ArrayList<>();

        try (var paths = Files.walk(Paths.get(projectRoot))) {
            paths.filter(path -> path.resolve("pom.xml").toFile().exists())
                    .forEach(pomPath -> {
                        try {
                            Map<String, Object> projectAnalysis = analyzeMavenProject(pomPath.getParent(), config);
                            projects.add(projectAnalysis);
                        } catch (Exception e) {
                            System.err.println("Error analyzing project at " + pomPath + ": " + e.getMessage());
                        }
                    });
        }

        return projects;
    }

    private Map<String, Object> analyzeMavenProject(Path projectPath, AnalysisConfig config) throws Exception {
        Map<String, Object> projectAnalysis = new HashMap<>();

        projectAnalysis.put("projectPath", projectPath.toString());
        projectAnalysis.put("projectName", projectPath.getFileName().toString());

        Map<String, Object> pomAnalysis = analyzePomFile(projectPath.resolve("pom.xml"));
        projectAnalysis.put("pom", pomAnalysis);

        Map<String, Object> sourceAnalysis = analyzeSourceCode(projectPath, config);
        projectAnalysis.put("sourceCode", sourceAnalysis);

        return projectAnalysis;
    }

    private Map<String, Object> analyzePomFile(Path pomPath) throws Exception {
        Map<String, Object> pomAnalysis = new HashMap<>();

        MavenXpp3Reader reader = new MavenXpp3Reader();
        try (var fileReader = new FileReader(pomPath.toFile())) {
            Model model = reader.read(fileReader);

            pomAnalysis.put("groupId", model.getGroupId());
            pomAnalysis.put("artifactId", model.getArtifactId());
            pomAnalysis.put("version", model.getVersion());
            pomAnalysis.put("packaging", model.getPackaging());
            pomAnalysis.put("name", model.getName());
            pomAnalysis.put("description", model.getDescription());

            var dependencies = model.getDependencies().stream()
                    .map(dep -> Map.of(
                            "groupId", Objects.toString(dep.getGroupId(), ""),
                            "artifactId", Objects.toString(dep.getArtifactId(), ""),
                            "version", Objects.toString(dep.getVersion(), ""),
                            "scope", Objects.toString(dep.getScope(), "compile"),
                            "type", Objects.toString(dep.getType(), "jar"),
                            "optional", String.valueOf(dep.isOptional())
                    ))
                    .collect(Collectors.toList());
            pomAnalysis.put("dependencies", dependencies);

            pomAnalysis.put("properties", model.getProperties());
            pomAnalysis.put("modules", model.getModules());

            if (model.getParent() != null) {
                var parent = model.getParent();
                pomAnalysis.put("parent", Map.of(
                        "groupId", parent.getGroupId(),
                        "artifactId", parent.getArtifactId(),
                        "version", parent.getVersion(),
                        "relativePath", Objects.toString(parent.getRelativePath(), "../pom.xml")
                ));
            }

            if (model.getBuild() != null) {
                var build = model.getBuild();
                pomAnalysis.put("build", Map.of(
                        "sourceDirectory", Objects.toString(build.getSourceDirectory(), "src/main/java"),
                        "testSourceDirectory", Objects.toString(build.getTestSourceDirectory(), "src/test/java"),
                        "outputDirectory", Objects.toString(build.getOutputDirectory(), "target/classes"),
                        "testOutputDirectory", Objects.toString(build.getTestOutputDirectory(), "target/test-classes")
                ));
            }

        } catch (XmlPullParserException e) {
            System.err.println("Error parsing POM file " + pomPath + ": " + e.getMessage());
            pomAnalysis.put("parseError", e.getMessage());
        }

        return pomAnalysis;
    }

    private Map<String, Object> analyzeSourceCode(Path projectPath, AnalysisConfig config) throws Exception {
        Map<String, Object> sourceAnalysis = new HashMap<>();

        Path mainJavaPath = projectPath.resolve("src/main/java");
        Path testJavaPath = projectPath.resolve("src/test/java");

        List<Map<String, Object>> mainSourceFiles = new ArrayList<>();
        List<Map<String, Object>> testSourceFiles = new ArrayList<>();

        if (Files.exists(mainJavaPath)) {
            mainSourceFiles = analyzeJavaFilesInDirectory(mainJavaPath, config);
        }

        if (config.includeTestCode() && Files.exists(testJavaPath)) {
            testSourceFiles = analyzeJavaFilesInDirectory(testJavaPath, config);
        }

        sourceAnalysis.put("mainSourceFiles", mainSourceFiles);
        sourceAnalysis.put("testSourceFiles", testSourceFiles);
        sourceAnalysis.put("mainSourceFileCount", mainSourceFiles.size());
        sourceAnalysis.put("testSourceFileCount", testSourceFiles.size());

        sourceAnalysis.put("statistics", generateCodeStatistics(mainSourceFiles, testSourceFiles));

        return sourceAnalysis;
    }

    private List<Map<String, Object>> analyzeJavaFilesInDirectory(Path directory, AnalysisConfig config) throws Exception {
        var javaFiles = Collections.synchronizedList(new ArrayList<Map<String, Object>>());
        var fileCount = new AtomicInteger(0);

        if (!Files.exists(directory)) {
            return javaFiles;
        }

        try (var paths = Files.walk(directory)) {
            paths.filter(path -> path.toString().endsWith(".java"))
                    .filter(path -> shouldIncludeFile(path, config))
                    .forEach(javaFile -> {
                        try {
                            if (Files.size(javaFile) > config.maxFileSize()) {
                                System.out.println("Skipping large file: " + javaFile + " (" + Files.size(javaFile) + " bytes)");
                                return;
                            }

                            var fileAnalysis = analyzeJavaFile(javaFile, config);
                            javaFiles.add(fileAnalysis);

                            int count = fileCount.incrementAndGet();
                            if (count % 100 == 0) {
                                System.out.println("Processed " + count + " Java files...");
                            }
                        } catch (Exception e) {
                            System.err.println("Error analyzing " + javaFile + ": " + e.getMessage());
                        }
                    });
        }

        System.out.println("Completed processing " + fileCount.get() + " Java files in " + directory);
        return javaFiles;
    }

    private Map<String, Object> analyzeJavaFile(Path javaFile, AnalysisConfig config) throws Exception {
        CompilationUnit cu = StaticJavaParser.parse(javaFile);
        Map<String, Object> fileAnalysis = new HashMap<>();

        fileAnalysis.put("filePath", javaFile.toString());
        fileAnalysis.put("fileName", javaFile.getFileName().toString());
        fileAnalysis.put("fileSize", Files.size(javaFile));

        cu.getPackageDeclaration().ifPresent(pkg -> {
            fileAnalysis.put("package", pkg.getNameAsString());
        });

        var imports = cu.getImports().stream()
                .map(imp -> imp.getNameAsString())
                .collect(Collectors.toList());
        fileAnalysis.put("imports", imports);
        fileAnalysis.put("importCount", imports.size());

        var types = new ArrayList<Map<String, Object>>();

        cu.findAll(ClassOrInterfaceDeclaration.class).forEach(cid -> {
            types.add(extractClassOrInterfaceInfo(cid, config));
        });

        cu.findAll(EnumDeclaration.class).forEach(ed -> {
            types.add(extractEnumInfo(ed, config));
        });

        cu.findAll(AnnotationDeclaration.class).forEach(ad -> {
            types.add(extractAnnotationInfo(ad, config));
        });

        fileAnalysis.put("types", types);

        var classCount = types.stream().filter(t -> "class".equals(t.get("kind"))).count();
        var interfaceCount = types.stream().filter(t -> "interface".equals(t.get("kind"))).count();
        var enumCount = types.stream().filter(t -> "enum".equals(t.get("kind"))).count();
        var annotationCount = types.stream().filter(t -> "annotation".equals(t.get("kind"))).count();

        fileAnalysis.put("classCount", classCount);
        fileAnalysis.put("interfaceCount", interfaceCount);
        fileAnalysis.put("enumCount", enumCount);
        fileAnalysis.put("annotationCount", annotationCount);

        var totalMethods = types.stream()
                .mapToLong(t -> getListValue(t, "methods").size())
                .sum();
        fileAnalysis.put("methodCount", totalMethods);

        var totalFields = types.stream()
                .mapToLong(t -> getListValue(t, "fields").size())
                .sum();
        fileAnalysis.put("fieldCount", totalFields);

        return fileAnalysis;
    }

    private Map<String, Object> extractClassOrInterfaceInfo(ClassOrInterfaceDeclaration cid, AnalysisConfig config) {
        var typeInfo = new HashMap<String, Object>();

        typeInfo.put("name", cid.getNameAsString());
        typeInfo.put("kind", cid.isInterface() ? "interface" : "class");
        typeInfo.put("isPublic", cid.isPublic());
        typeInfo.put("isAbstract", cid.isAbstract());
        typeInfo.put("isFinal", cid.isFinal());
        typeInfo.put("isStatic", cid.isStatic());
        typeInfo.put("lineNumber", cid.getRange().map(r -> r.begin.line).orElse(-1));

        typeInfo.put("modifiers", cid.getModifiers().stream()
                .map(m -> m.getKeyword().asString())
                .collect(Collectors.toList()));

        typeInfo.put("annotations", cid.getAnnotations().stream()
                .map(ann -> ann.getNameAsString())
                .collect(Collectors.toList()));

        typeInfo.put("extendedTypes", cid.getExtendedTypes().stream()
                .map(t -> t.getNameAsString())
                .collect(Collectors.toList()));

        typeInfo.put("implementedTypes", cid.getImplementedTypes().stream()
                .map(t -> t.getNameAsString())
                .collect(Collectors.toList()));

        typeInfo.put("typeParameters", cid.getTypeParameters().stream()
                .map(tp -> tp.getNameAsString())
                .collect(Collectors.toList()));

        if (config.detailedMethodAnalysis()) {
            typeInfo.put("methods", cid.getMethods().stream()
                    .map(method -> extractMethodInfo(method))
                    .collect(Collectors.toList()));

            var fields = new ArrayList<Map<String, Object>>();
            cid.getFields().forEach(field -> {
                field.getVariables().forEach(variable -> {
                    fields.add(extractFieldInfo(field, variable));
                });
            });
            typeInfo.put("fields", fields);

            typeInfo.put("constructors", cid.getConstructors().stream()
                    .map(constructor -> extractConstructorInfo(constructor))
                    .collect(Collectors.toList()));
        }

        return typeInfo;
    }

    private Map<String, Object> extractEnumInfo(EnumDeclaration ed, AnalysisConfig config) {
        var enumInfo = new HashMap<String, Object>();

        enumInfo.put("name", ed.getNameAsString());
        enumInfo.put("kind", "enum");
        enumInfo.put("isPublic", ed.isPublic());
        enumInfo.put("lineNumber", ed.getRange().map(r -> r.begin.line).orElse(-1));

        enumInfo.put("constants", ed.getEntries().stream()
                .map(entry -> entry.getNameAsString())
                .collect(Collectors.toList()));

        if (config.detailedMethodAnalysis()) {
            enumInfo.put("methods", ed.getMethods().stream()
                    .map(method -> extractMethodInfo(method))
                    .collect(Collectors.toList()));

            var fields = new ArrayList<Map<String, Object>>();
            ed.getFields().forEach(field -> {
                field.getVariables().forEach(variable -> {
                    fields.add(extractFieldInfo(field, variable));
                });
            });
            enumInfo.put("fields", fields);
        }

        return enumInfo;
    }

    private Map<String, Object> extractAnnotationInfo(AnnotationDeclaration ad, AnalysisConfig config) {
        var annotationInfo = new HashMap<String, Object>();

        annotationInfo.put("name", ad.getNameAsString());
        annotationInfo.put("kind", "annotation");
        annotationInfo.put("isPublic", ad.isPublic());
        annotationInfo.put("lineNumber", ad.getRange().map(r -> r.begin.line).orElse(-1));

        if (config.detailedMethodAnalysis()) {
            annotationInfo.put("elements", ad.getMethods().stream()
                    .map(method -> extractMethodInfo(method))
                    .collect(Collectors.toList()));
        }

        return annotationInfo;
    }

    private Map<String, Object> extractMethodInfo(MethodDeclaration method) {
        var methodInfo = new HashMap<String, Object>();

        methodInfo.put("name", method.getNameAsString());
        methodInfo.put("returnType", method.getType().asString());
        methodInfo.put("isPublic", method.isPublic());
        methodInfo.put("isPrivate", method.isPrivate());
        methodInfo.put("isProtected", method.isProtected());
        methodInfo.put("isStatic", method.isStatic());
        methodInfo.put("isAbstract", method.isAbstract());
        methodInfo.put("isFinal", method.isFinal());
        methodInfo.put("lineNumber", method.getRange().map(r -> r.begin.line).orElse(-1));

        var parameters = method.getParameters().stream()
                .map(param -> Map.of(
                        "name", param.getNameAsString(),
                        "type", param.getType().asString()
                ))
                .collect(Collectors.toList());
        methodInfo.put("parameters", parameters);

        methodInfo.put("typeParameters", method.getTypeParameters().stream()
                .map(tp -> tp.getNameAsString())
                .collect(Collectors.toList()));

        methodInfo.put("annotations", method.getAnnotations().stream()
                .map(ann -> ann.getNameAsString())
                .collect(Collectors.toList()));

        methodInfo.put("thrownExceptions", method.getThrownExceptions().stream()
                .map(ex -> ex.toString())
                .collect(Collectors.toList()));

        return methodInfo;
    }

    private Map<String, Object> extractFieldInfo(FieldDeclaration field, VariableDeclarator variable) {
        var fieldInfo = new HashMap<String, Object>();

        fieldInfo.put("name", variable.getNameAsString());
        fieldInfo.put("type", variable.getType().asString());
        fieldInfo.put("isPublic", field.isPublic());
        fieldInfo.put("isPrivate", field.isPrivate());
        fieldInfo.put("isProtected", field.isProtected());
        fieldInfo.put("isStatic", field.isStatic());
        fieldInfo.put("isFinal", field.isFinal());
        fieldInfo.put("lineNumber", variable.getRange().map(r -> r.begin.line).orElse(-1));

        variable.getInitializer().ifPresent(init -> {
            fieldInfo.put("initializer", init.toString());
        });

        fieldInfo.put("annotations", field.getAnnotations().stream()
                .map(ann -> ann.getNameAsString())
                .collect(Collectors.toList()));

        return fieldInfo;
    }

    private Map<String, Object> extractConstructorInfo(ConstructorDeclaration constructor) {
        var constructorInfo = new HashMap<String, Object>();

        constructorInfo.put("name", constructor.getNameAsString());
        constructorInfo.put("isPublic", constructor.isPublic());
        constructorInfo.put("isPrivate", constructor.isPrivate());
        constructorInfo.put("isProtected", constructor.isProtected());
        constructorInfo.put("lineNumber", constructor.getRange().map(r -> r.begin.line).orElse(-1));

        var parameters = constructor.getParameters().stream()
                .map(param -> Map.of(
                        "name", param.getNameAsString(),
                        "type", param.getType().asString()
                ))
                .collect(Collectors.toList());
        constructorInfo.put("parameters", parameters);

        constructorInfo.put("annotations", constructor.getAnnotations().stream()
                .map(ann -> ann.getNameAsString())
                .collect(Collectors.toList()));

        constructorInfo.put("thrownExceptions", constructor.getThrownExceptions().stream()
                .map(ex -> ex.toString())
                .collect(Collectors.toList()));

        return constructorInfo;
    }

    private Map<String, Object> generateCodeStatistics(List<Map<String, Object>> mainFiles,
                                                       List<Map<String, Object>> testFiles) {
        var stats = new HashMap<String, Object>();

        var totalMainFiles = mainFiles.size();
        var totalTestFiles = testFiles.size();

        long mainClasses = mainFiles.stream().mapToLong(f -> getLongValue(f, "classCount")).sum();
        long mainInterfaces = mainFiles.stream().mapToLong(f -> getLongValue(f, "interfaceCount")).sum();
        long mainEnums = mainFiles.stream().mapToLong(f -> getLongValue(f, "enumCount")).sum();
        long mainMethods = mainFiles.stream().mapToLong(f -> getLongValue(f, "methodCount")).sum();
        long mainFields = mainFiles.stream().mapToLong(f -> getLongValue(f, "fieldCount")).sum();

        long testClasses = testFiles.stream().mapToLong(f -> getLongValue(f, "classCount")).sum();
        long testInterfaces = testFiles.stream().mapToLong(f -> getLongValue(f, "interfaceCount")).sum();
        long testEnums = testFiles.stream().mapToLong(f -> getLongValue(f, "enumCount")).sum();
        long testMethods = testFiles.stream().mapToLong(f -> getLongValue(f, "methodCount")).sum();
        long testFields = testFiles.stream().mapToLong(f -> getLongValue(f, "fieldCount")).sum();

        stats.put("totalFiles", totalMainFiles + totalTestFiles);
        stats.put("mainFiles", totalMainFiles);
        stats.put("testFiles", totalTestFiles);
        stats.put("totalClasses", mainClasses + testClasses);
        stats.put("totalInterfaces", mainInterfaces + testInterfaces);
        stats.put("totalEnums", mainEnums + testEnums);
        stats.put("totalMethods", mainMethods + testMethods);
        stats.put("totalFields", mainFields + testFields);
        stats.put("mainClasses", mainClasses);
        stats.put("mainInterfaces", mainInterfaces);
        stats.put("mainEnums", mainEnums);
        stats.put("mainMethods", mainMethods);
        stats.put("mainFields", mainFields);
        stats.put("testClasses", testClasses);
        stats.put("testInterfaces", testInterfaces);
        stats.put("testEnums", testEnums);
        stats.put("testMethods", testMethods);
        stats.put("testFields", testFields);

        return stats;
    }

    private Map<String, Object> generateOverallStatistics(List<Map<String, Object>> projects) {
        var overallStats = new HashMap<String, Object>();

        var totalProjects = projects.size();

        var totalDependencies = projects.stream()
                .mapToLong(p -> getListValue((Map<String, Object>) p.get("pom"), "dependencies").size())
                .sum();

        var totalMainFiles = projects.stream()
                .mapToLong(p -> getLongValue((Map<String, Object>) p.get("sourceCode"), "mainSourceFileCount"))
                .sum();

        var totalTestFiles = projects.stream()
                .mapToLong(p -> getLongValue((Map<String, Object>) p.get("sourceCode"), "testSourceFileCount"))
                .sum();

        var codeStats = projects.stream()
                .map(p -> (Map<String, Object>) ((Map<?, ?>) p.get("sourceCode")).get("statistics"))
                .reduce(new HashMap<>(), (acc, stats) -> {
                    if (stats != null) {
                        stats.forEach((key, value) -> {
                            if (value instanceof Number numberValue) {
                                long current = getLongValue(acc, key.toString());
                                acc.put(key.toString(), current + numberValue.longValue());
                            }
                        });
                    }
                    return acc;
                });

        overallStats.put("totalProjects", totalProjects);
        overallStats.put("totalDependencies", totalDependencies);
        overallStats.put("totalMainFiles", totalMainFiles);
        overallStats.put("totalTestFiles", totalTestFiles);
        overallStats.put("codeStatistics", codeStats);

        return overallStats;
    }

    private void cloneRepository(String repoUrl, String localPath, String username, String token)
            throws GitAPIException {
        System.out.println("Cloning repository to: " + localPath);

        var cloneCommand = Git.cloneRepository()
                .setURI(repoUrl)
                .setDirectory(new File(localPath))
                .setCloneSubmodules(false)
                .setProgressMonitor(new SimpleProgressMonitor());

        if (username != null && token != null) {
            cloneCommand.setCredentialsProvider(new UsernamePasswordCredentialsProvider(username, token));
        }

        try (var git = cloneCommand.call()) {
            System.out.println("Repository cloned successfully");
        }
    }

    // FIXED: Updated ProgressMonitor with showDuration method
    private static class SimpleProgressMonitor implements ProgressMonitor {
        @Override
        public void start(int totalTasks) {
            System.out.println("Starting clone with " + totalTasks + " tasks");
        }

        @Override
        public void beginTask(String title, int totalWork) {
            System.out.println("Beginning: " + title + " (" + totalWork + " items)");
        }

        @Override
        public void update(int completed) {
            // Progress updates - can be enhanced with percentage
        }

        @Override
        public void endTask() {
            System.out.println("Task completed");
        }

        @Override
        public boolean isCancelled() {
            return false;
        }

        // NEW: Added in JGit 7.4
        @Override
        public void showDuration(boolean enabled) {
            // Control whether to show duration of operations
            System.out.println("Duration tracking: " + (enabled ? "enabled" : "disabled"));
        }
    }

    private String extractRepoName(String repoUrl) {
        return Arrays.stream(repoUrl.split("/"))
                .reduce((first, second) -> second)
                .map(name -> name.replace(".git", ""))
                .orElse("repository");
    }

    private void printSummary(Map<String, Object> analysis) {
        System.out.println("\n=== ANALYSIS SUMMARY ===");
        System.out.println("Repository: " + analysis.get("repositoryUrl"));
        System.out.println("Analysis Date: " + analysis.get("analysisDate"));

        @SuppressWarnings("unchecked")
        var projects = (List<Map<String, Object>>) analysis.get("mavenProjects");
        System.out.println("Maven Projects Found: " + projects.size());

        for (var project : projects) {
            System.out.println("\nProject: " + project.get("projectName"));

            var pom = (Map<String, Object>) project.get("pom");
            System.out.printf("  Artifact: %s:%s:%s%n",
                    pom.get("groupId"), pom.get("artifactId"), pom.get("version"));

            var deps = getListValue(pom, "dependencies");
            System.out.println("  Dependencies: " + deps.size());

            var sourceCode = (Map<String, Object>) project.get("sourceCode");
            System.out.println("  Main Source Files: " + getLongValue(sourceCode, "mainSourceFileCount"));
            System.out.println("  Test Source Files: " + getLongValue(sourceCode, "testSourceFileCount"));
        }
    }

    public void cleanup() {
        try {
            Files.walk(Paths.get(tempDir))
                    .sorted((a, b) -> -a.compareTo(b))
                    .map(Path::toFile)
                    .forEach(File::delete);
            System.out.println("Temporary files cleaned up");
        } catch (IOException e) {
            System.err.println("Cleanup failed: " + e.getMessage());
        }
    }
}