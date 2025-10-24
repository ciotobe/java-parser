java -jar target/javaparser-0.0.1-SNAPSHOT-jar-with-dependencies.jar jp.co.jri.analyzer.GitHubMavenAnalyzer https://github.com/spring-projects/spring-boot.git my-analysis.json

mvn compile exec:java -Dexec.mainClass="jp.co.jri.analyzer.GitHubMavenAnalyzer" -Dexec.args="https://github.com/ciotobe/sftp.git output.json