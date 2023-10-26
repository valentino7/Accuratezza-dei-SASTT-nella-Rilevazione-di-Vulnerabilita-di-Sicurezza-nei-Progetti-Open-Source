package controller;

import entity.FileTrack;
import entity.GitInfo;
import entity.VulasEntry;
import utils.Constants;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.ResetCommand;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.diff.DiffEntry;
import org.eclipse.jgit.diff.DiffFormatter;
import org.eclipse.jgit.diff.Edit;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.ObjectReader;
import org.eclipse.jgit.patch.FileHeader;
import org.eclipse.jgit.patch.HunkHeader;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.eclipse.jgit.treewalk.CanonicalTreeParser;
import org.eclipse.jgit.util.io.DisabledOutputStream;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static IO.ReaderInputs.getAbsolute;
import static common.GitCommon.getParentCommit;

public class RunnerCreateDatasetCWEClass {


    public static HashMap<String, GitInfo> getMethodName(File gitDirectory, String filename, FileTrack f) {
        ExtractorLineNumber e = new ExtractorLineNumber();
        //File f = new File(gitDirectory, entry.getNewPath());
        //System.out.println( entry.getNewPath() );
        try {

            return ExtractorLineNumber.getMethodLineNumbers(gitDirectory, filename, f).gethMethodPosition();


        } catch (Exception ex) {
            return null;
        }
    }

    public static void copyFile(File from, File to) throws IOException {

        if (!to.exists()) {
            to.createNewFile();
        }

        try (
                FileChannel in = new FileInputStream(from).getChannel();
                FileChannel out = new FileOutputStream(to).getChannel()) {

            out.transferFrom(in, 0, in.size());
        }
    }

    // Sposta i file .java e .class nella cartella result di questo progetto e poi avvia i tool
    public static void createResultDirectory(String compilator, String path, String cweId, Boolean badness, String fixCommit, String projectName, String parentCommit) throws IOException {
        String fileName = path.split("/")[path.split("/").length - 1];
        String srcPath = getAbsolute(Constants.PATH_PROJECT_ROOT) + "\\" +projectName + fixCommit + "\\" + path;

        System.err.println(compilator);

        if (srcPath.contains("test") && projectName.equals("tomcat"))
            return;
        if (compilator.contains("ant")) {
            // ANT CASE
            // Creazione dei path per i risultati delle classi
            System.out.println(srcPath);
            String finalClassPath="";
            String classPathIntermediate = srcPath.replace(".java", ".class");


            if(projectName.equals("tomcat")){
                finalClassPath = classPathIntermediate.replace("java", "output\\classes");
            }
            else if (srcPath.contains("jBCrypt")) {
                finalClassPath = classPathIntermediate.replace("src", "build");
            } else {
                finalClassPath = classPathIntermediate.replace("src", "build\\classes");
            }
            String classFilename = fileName.replace(".java", ".class");

            // Spostamento file .class
            Files.createDirectories(Paths.get(getAbsolute(Constants.JAVA_SRC) + "\\" + cweId));
            // Spostamento file .java
            Files.createDirectories(Paths.get(getAbsolute(Constants.JAVA_SRC) + "\\" + cweId));

            if (!badness) {
                copyFile(new File(finalClassPath), new File(getAbsolute(Constants.JAVA_CLASS) + "\\" + cweId + "\\good_" + fixCommit + "_" + classFilename));
                copyFile(new File(

                ), new File(getAbsolute(Constants.JAVA_SRC) + "\\" + cweId + "\\good_" + fixCommit + "_" + fileName));
            } else {
                copyFile(new File(finalClassPath), new File(getAbsolute(Constants.JAVA_CLASS) + "\\" + cweId + "\\bad_" + fixCommit + "_" + classFilename));
                copyFile(new File(getAbsolute(getAbsolute(Constants.PATH_PROJECT_ROOT) + "\\" +projectName + parentCommit + "\\" + path)), new File(getAbsolute(Constants.JAVA_SRC) + "\\" + cweId + "\\bad_" + fixCommit + "_" + fileName));
            }
        }
        if (compilator.contains("mvn")) {
            if (srcPath.contains("test") )
                return;
            // MVN CASE
            // Creazione dei path per i risultati delle classi
            if (path.contains("thrift")) {
                path = "F:\\Valentino\\IdeaProjects\\thrift\\contrib\\thrift-maven-plugin";
            }
            String classPathIntermediate = srcPath.replace(".java", ".class");
            String finalClassPath="";

            if(classPathIntermediate.contains("Openfire")){
                finalClassPath = classPathIntermediate.replace("src/java", "xmppserver\\target\\classes");
            } else if (classPathIntermediate.contains("struts")) {
                finalClassPath = classPathIntermediate.replace("src/main/java", "target\\classes");
            }else if(classPathIntermediate.contains("prime-jwt")){
                finalClassPath = classPathIntermediate.replace("src/main/java", "target\\classes");
            }
            else {
                finalClassPath = classPathIntermediate.replace("src\\java", "target\\classes");
            }
            String classFilename = fileName.replace(".java", ".class");

            // Spostamento file .class
            Files.createDirectories(Paths.get(getAbsolute(Constants.JAVA_CLASS) + "\\" + cweId));
            // Spostamento file .java
            Files.createDirectories(Paths.get(getAbsolute(Constants.JAVA_SRC) + "\\" + cweId));

            if (!badness) {
                copyFile(new File(finalClassPath), new File(getAbsolute(Constants.JAVA_CLASS) + "\\" + cweId + "\\good_" + fixCommit + "_" + classFilename));
                copyFile(new File(getAbsolute(Constants.PATH_PROJECT_ROOT) + "\\" +projectName + fixCommit + "\\" + path), new File(getAbsolute(Constants.JAVA_SRC) + "\\" + cweId + "\\good_" + fixCommit + "_" + fileName));
            } else {
                copyFile(new File(finalClassPath), new File(getAbsolute(Constants.JAVA_CLASS) + "\\" + cweId + "\\bad_" + fixCommit + "_" + classFilename));
                copyFile(new File(getAbsolute(Constants.PATH_PROJECT_ROOT) + "\\" +projectName + parentCommit +"\\" + path), new File(getAbsolute(Constants.JAVA_SRC) + "\\" + cweId + "\\bad_" + fixCommit + "_" + fileName));
            }
        }
        if (compilator.contains("gradle")) {
            System.out.println("Else in compialtore");
        }
    }



    // Sposta i file .java nella cartella result di questo progetto e poi avvia i tool
    public static void createResultDirectoryWithoutClass(String path, String cweId, Boolean badness, String fixCommit, String projectName, String parentCommit) throws IOException {
        String fileName = path.split("/")[path.split("/").length - 1];
        String srcPath = Constants.PATH_PROJECT_ROOT + projectName + fixCommit + "\\" + path;


        // Spostamento file .java
        System.err.println(Constants.JAVA_SRC + "\\" + cweId);
        System.err.println(srcPath);
        System.err.println(Constants.PATH_PROJECT_ROOT + projectName + fixCommit + "\\" + path);
        System.err.println(Constants.JAVA_SRC + "\\" + cweId + "\\good_" + fixCommit + "_" + fileName);
        if (srcPath.contains("test") )
            return;

        Files.createDirectories(Paths.get(Constants.JAVA_SRC + "\\" + cweId));

        if (!badness) {
            copyFile(new File(Constants.PATH_PROJECT_ROOT + projectName + fixCommit + "\\" + path), new File(Constants.JAVA_SRC+ "\\" + cweId + "\\good_" + fixCommit + "_" + fileName));
        } else {
            copyFile(new File(Constants.PATH_PROJECT_ROOT + projectName + parentCommit +"\\" + path), new File(Constants.JAVA_SRC + "\\" + cweId + "\\bad_" + fixCommit + "_" + fileName));
        }

    }

    public static boolean has(ArrayList<String> cwes, String target){
        for (String s: cwes){
            if (s.equals(target))
                return true;
        }
        return false;
    }

    public static void fillHashmapMethod(String projectName, ArrayList<String> cveList, HashMap<String, String> mappingCve, HashMap<String, FileTrack> hFileTrackGit,
                                         Boolean label, List<DiffEntry> entries, File gitDirectory,
                                         DiffFormatter diffFormatter, String fixCommit, String parentCommit)
            throws IOException {

        int count = 0;
        for (DiffEntry entry : entries) {
            /*System.out.println( entry.getChangeType() );
            System.out.println( entry.getNewPath() );
            System.out.println( entry.getOldPath() );
            System.out.println( entry.getDiffAttribute());
            System.out.println( entry);*/
            String actualPath;
            if (label)
                actualPath = entry.getOldPath();
            else
                actualPath = entry.getNewPath();
            System.err.println("lABEL+ "+label);
            System.err.println("lABEL+ "+actualPath);
            if (actualPath.contains(".java") && !actualPath.contains("test")) {

                FileTrack f;
                if (!hFileTrackGit.containsKey(actualPath + "$" + label.toString() + "$" + fixCommit)) {
                    f = new FileTrack();
                    f.setProjectName(projectName);
                    f.setFileName(actualPath);
                    f.setBadness(label);
                    f.setParentCommit(parentCommit);
                    f.setFixCommitID(fixCommit);
                    f.setCWE("");

                    ArrayList<String> cwes = new ArrayList<>();
                    for (String cve : cveList){
                        if (!has(cwes,  mappingCve.get(cve)) ){
                            cwes.add(mappingCve.get(cve));

                            System.out.println(mappingCve.get(cve));
                            if (!f.getCWE().equals(""))
                                f.setCWE(mappingCve.get(cve) + "_" + f.getCWE());
                            else
                                f.setCWE(mappingCve.get(cve));
                        }
                    }
                } else
                    f = hFileTrackGit.get(actualPath + "$" + label.toString() + "$" + fixCommit);

                /*
                        ANALISI FILE CHE HANNO CAMBIATO NOME
                 */
                if (!entry.getOldPath().equals(entry.getNewPath())) {
                    count += 1;
                    System.out.println("Nome file cambiato" + fixCommit + "$" + gitDirectory + "$" + String.valueOf(count));
                }
                /*System.out.println( entry);
                System.out.println( entry.getChangeType() );
                System.out.println( entry.getOldPath() );
                System.out.println( entry.getNewPath() );*/

                // Estraggo i range modificati
                FileHeader fileHeader = diffFormatter.toFileHeader(entry);
                List<? extends HunkHeader> hunks = fileHeader.getHunks();
                boolean error = false;
                for (HunkHeader hunk : hunks) {
                    /*System.out.println( hunk );
                    System.out.println( hunk.getNewStartLine() );
                    System.out.println( hunk.getNewLineCount() );
                    System.out.println( hunk.toEditList().toString());*/

                    for (Edit e : hunk.toEditList()) {
                        GitInfo myPosition;
                        // File A è LA COMMIT MENO RECENTE (quella buggata)
                        if (!label) {
                            System.out.println( e.getBeginB() );
                            System.out.println( e.getEndB() );
                            myPosition = new GitInfo(e.getBeginB(), e.getEndB());
                        } else {
                            System.out.println( e.getBeginA() );
                            System.out.println( e.getEndA() );
                            myPosition = new GitInfo(e.getBeginA(), e.getEndA());
                        }
                        myPosition.setChangeType(e.getType().toString());

                        FileTrack tmpf = new FileTrack();
                        tmpf.gethMethodPosition().put("", myPosition);


                        /**
                         * Viene aggiunto il metodo solo se la linea dove è avvenuto il cambiamento
                         * matcha con la linea dove è presente il metodo
                         * vengono quindi escluse le righe che non riferiscono a nessun metodo
                         */
                        HashMap<String, GitInfo> hp = getMethodName(gitDirectory, f.getFileName(), tmpf);
                        if (hp == null){
                            error = true;
                            System.out.println("ERRORE PARSER="+f.getFileName());
                            break;
                        }
                        f.gethMethodPosition().putAll(hp);

                        /*for (Map.Entry<String, GitInfo> p : f.gethMethodPosition().entrySet()) {
                            createResultDirectoryWithoutClass(f.getFileName(), f.getCWE(), f.getBadness(), fixCommit, projectName, parentCommit);
                        }*/
                    }
                    if (error)
                        break;
                }
                if (!error) {
                    System.out.println("              \n");
                    if (f.gethMethodPosition().isEmpty()){
                        System.out.println("Il file non ha metodi toccati: ");
                        continue;
                    }
                    // Creazione delle directory di output
                    createResultDirectoryWithoutClass(f.getFileName(), f.getCWE(), f.getBadness(), fixCommit, projectName, parentCommit);
                    hFileTrackGit.put(actualPath + "$" + label.toString() + "$" + f.getFixCommitID(), f);
                }
            }
        }
    }


    public static void run(VulasEntry e, String projectName, HashMap<String, String> mappingCve, HashMap<String, FileTrack> hFileTrackGit) throws IOException, GitAPIException {
        File gitDirectory = new File(getAbsolute(Constants.PATH_PROJECT_REPOSITORIES +projectName));

        Git git;
        FileRepositoryBuilder repositoryBuilder = new FileRepositoryBuilder();
        repositoryBuilder.addCeilingDirectory(gitDirectory);
        repositoryBuilder.findGitDir(gitDirectory);

        git = new Git(repositoryBuilder.build());


        ObjectReader reader = git.getRepository().newObjectReader();
        CanonicalTreeParser oldTreeIter = new CanonicalTreeParser();

        String parentCommit = getParentCommit(git, e.getCommitID());


        ObjectId oldTree = git.getRepository().resolve(parentCommit + "^{tree}");

        oldTreeIter.reset(reader, oldTree);


        CanonicalTreeParser newTreeIter = new CanonicalTreeParser();
        ObjectId newTree = null;

        newTree = git.getRepository().resolve(e.getCommitID() + "^{tree}");

        newTreeIter.reset(reader, newTree);

        //ObjectId newTree = git.getRepository().resolve( "HEAD^{tree}" );


        DiffFormatter diffFormatter = new DiffFormatter(DisabledOutputStream.INSTANCE);
        diffFormatter.setRepository(git.getRepository());
        List<DiffEntry> entries = diffFormatter.scan(oldTreeIter, newTreeIter);

        System.err.println(e.getFixCommit());
        System.err.println(e.getProjectUrl());
        git.reset()
                .setRef(e.getFixCommit())
                .setMode(ResetCommand.ResetType.HARD)
                .call();
        fillHashmapMethod(projectName,e.getCveids(), mappingCve, hFileTrackGit, Boolean.FALSE, entries, gitDirectory, diffFormatter, e.getCommitID(), "");


        System.err.println(parentCommit);
        git.reset()
                .setRef(parentCommit)
                .setMode(ResetCommand.ResetType.HARD)
                .call();

        fillHashmapMethod(projectName,e.getCveids(), mappingCve, hFileTrackGit, Boolean.TRUE, entries, gitDirectory, diffFormatter, e.getFixCommit(), parentCommit);

    }
}
