/**
 *     Pre requisiti: repository dei progetti scaricati
 *        Questo script crea le cartelle inerenti alla fix e old commit per le repository scaricate
 */


package controller;

import entity.VulasEntry;
import IO.ReaderInputs;
import utils.Constants;
import org.apache.commons.io.FileUtils;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.ResetCommand;
import org.eclipse.jgit.diff.DiffEntry;
import org.eclipse.jgit.diff.DiffFormatter;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.ObjectReader;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.eclipse.jgit.treewalk.CanonicalTreeParser;
import org.eclipse.jgit.util.io.DisabledOutputStream;
import java.io.*;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.List;

import static IO.ReaderInputs.getAbsolute;
import static common.GitCommon.getParentCommit;

public class CreateFixParentDir {



    public static Boolean createDir(String projectName, String commit){
        boolean flag=true;
        try {
            File file = new File(getAbsolute(Constants.PATH_PROJECT_ROOT+projectName+commit));
            //file.createNewFile();
            flag = file.mkdir();
            System.out.print("Directory created? " + flag);
        } catch(Exception e) {
            e.printStackTrace();
        }
        return flag;
    }


    public static void copyDir(String projectName, String commit){
        File from = new File( getAbsolute(Constants.PATH_PROJECT_REPOSITORIES + projectName));
        File to = new File(getAbsolute(Constants.PATH_PROJECT_ROOT+projectName+commit));

        try {
            FileUtils.copyDirectory(from, to, new FileFilter() {
                public boolean accept(File pathname) {
                    // We don't want 'Sub3' folder to be imported
                    // + look at the settings to decide if some format needs to be
                    // excluded
                    String name = pathname.getAbsolutePath();
                    //System.out.println(name);
                    if (name.contains(".git"))
                        return false;
                    return true;
                }
            }, true);
            System.out.println("Directory moved successfully.");
        }
        catch (IOException ex) {
            ex.printStackTrace();
        }
    }


    public static String getProjectPathStr(String projectName) {
        String projectPath = "";
        projectPath = getAbsolute(Constants.PATH_PROJECT_REPOSITORIES + projectName);
        return projectPath;
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

    /**
     * Si cicla sulle entries vulas, ogni riga è formata da:
     * cve_id; link al repository del progetto; fix commit
     *
     * Possono esserci quindi due righe con stesso link al repository e diverso cve_id
     * Si posiziona git repository sulla cartella scaricata del progetto e da lì è possibile lanciare i comandi reset per cambiare commit
     * Si crea il path per salvare la repository del progetto per la fix commmit: dir/nome_progetto+fixcommit
     * Se la directory non esiste viene fatto un reset alla fix commit e quindi copiato il contenuto
     * Si esegue lo stesso processo di copiatura per la commit precedente alla fix (parent)

     * directory di input:  Constants.PATH_VULAS_DB
     * directory di input per leggere le repository: Constants.PATH_PROJECT_REPOSITORIES
     * directory di output per salvare i progetti: Constants.PATH_PROJECT_ROOT
     */
    public static void main(String args[]) throws IOException {

        ArrayList<VulasEntry> vulasEntries = ReaderInputs.readVulasCsv(Constants.PATH_VULAS_DB);

        int size = 0;
        for (VulasEntry v : vulasEntries) {
            size += 1;

            String projectName = v.getProjectUrl().split("/")[v.getProjectUrl().split("/").length - 1];
            String projectPath = getProjectPathStr(projectName);
            System.out.println("Project Path: "+projectPath);
            System.out.println("fixCommit: " + v.getCommitID());


            File gitDirectory = new File(projectPath);
            Git git;
            FileRepositoryBuilder repositoryBuilder = new FileRepositoryBuilder();
            repositoryBuilder.addCeilingDirectory(gitDirectory);
            repositoryBuilder.findGitDir(gitDirectory);

            try {
                git = new Git(repositoryBuilder.build());
                ObjectReader reader = git.getRepository().newObjectReader();
                CanonicalTreeParser oldTreeIter = new CanonicalTreeParser();
                String parentCommit = null;
                parentCommit = getParentCommit(git, v.getCommitID());

                if(createDir(projectName, v.getCommitID())) {
                    ObjectId oldTree = null;
                    oldTree = git.getRepository().resolve(parentCommit + "^{tree}");

                    oldTreeIter.reset(reader, oldTree);

                    CanonicalTreeParser newTreeIter = new CanonicalTreeParser();
                    ObjectId newTree = null;
                    newTree = git.getRepository().resolve(v.getCommitID() + "^{tree}");
                    newTreeIter.reset(reader, newTree);
                    DiffFormatter diffFormatter = new DiffFormatter(DisabledOutputStream.INSTANCE);
                    diffFormatter.setRepository(git.getRepository());
                    List<DiffEntry> entries = diffFormatter.scan(oldTreeIter, newTreeIter);

                    git.reset()
                            .setRef(v.getCommitID())
                            .setMode(ResetCommand.ResetType.HARD)
                            .call();
                    copyDir(projectName, v.getCommitID());
                }

                if(createDir(projectName, parentCommit)){
                    git.reset()
                            .setRef(parentCommit)
                            .setMode(ResetCommand.ResetType.HARD)
                            .call();
                    copyDir(projectName, parentCommit);
                }
            }catch (Exception ex) {
                System.err.println("ERRORE:"+ v.getProjectUrl()+","+v.getCommitID());
                ex.printStackTrace();
                continue;
            }
        }
        System.out.println("Il seguente numero di directory create deve essere uguale al numero di progetti contenuti nel file di input vulas");
        System.out.println(size);

    }

}