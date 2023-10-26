package controller;

import org.apache.commons.io.filefilter.FileFilterUtils;
import utils.Constants;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;

import static IO.ReaderInputs.getAbsolute;
import static IO.ReaderInputs.startProcess;

public class RunnerTools {


    public static void runCommand(String cweName,String fileName, String tool) throws IOException, InterruptedException {
        ProcessBuilder processBuilder = new ProcessBuilder(); // pass in your command and options;


        if (tool.equals("spotbugs"))
            processBuilder.command("ubuntu", "run", "cd", Constants.BIN_TOOLS + "/spotbugs-4.7.3", "&&", "./bin/spotbugs", "-textui", "-bugCategories", "SECURITY", "-low", "-xml=" + Constants.REPORT_RESULTS_RUNNER_TOOLS + "spotbugs/" + cweName + "_" + fileName + ".xml", "-auxclasspath", Constants.JAVA_CLASS_RUNNER_TOOLS, "-sourcepath", Constants.JAVA_SRC_RUNNER_TOOLS + cweName + "/" + fileName + ".java", Constants.JAVA_CLASS_RUNNER_TOOLS + "/" + cweName + "/" + fileName + ".class");
        else if (tool.equals("findsec"))
            processBuilder.command("ubuntu", "run", "cd", Constants.BIN_TOOLS + "/spotbugs-4.7.3", "&&", "./bin/spotbugs", "-textui", "-bugCategories", "SECURITY", "-pluginList", "findsecbugs-plugin-1.12.0.jar", "-low", "-xml=" + Constants.REPORT_RESULTS_RUNNER_TOOLS + "findsec/" + cweName + "_" + fileName + ".xml", "-auxclasspath", Constants.JAVA_CLASS_RUNNER_TOOLS, "-sourcepath", Constants.JAVA_SRC_RUNNER_TOOLS + cweName + "/" + fileName + ".java", Constants.JAVA_CLASS_RUNNER_TOOLS + "/" + cweName + "/" + fileName + ".class");
        else if (tool.equals("pmd")){
            // ./run.sh pmd -d /mnt/c/Users/Valentino/Documenti/Test/src/CWE23_Relative_Path_Traversal__connect_tcp_01.java -f xml --report-file /mnt/c/Users/Valentino/Documenti/Universita/PMDtest.xml -R rulesets/java/quickstart.xml
            fileName = fileName.replace("$", "\\$");
            System.out.println(fileName);

            processBuilder.command(
                "ubuntu", "run", "cd", Constants.BIN_TOOLS + "/pmd-bin-6.44.0", "&&", "./bin/run.sh",
                "pmd", "-d",
                Constants.JAVA_SRC_RUNNER_TOOLS + cweName + "/" + fileName + ".java",
                "-f", "xml", "--report-file",
                Constants.PMD_PATH_REPORT_RESULT_MNT + cweName + "\\$" + fileName,
                "-R", "rulesets/java/quickstart.xml");
    }else
            processBuilder.command("ubuntu","run","cd",Constants.BIN_TOOLS+"/jlint-3.1.2","&&","./jlint", "+verbose", "+history",  Constants.REPORT_RESULTS_RUNNER_TOOLS+"jlint/"+cweName+"_"+fileName, "-source", Constants.JAVA_SRC_RUNNER_TOOLS +cweName+"/"+fileName+".java" , Constants.JAVA_CLASS_RUNNER_TOOLS+"/"+cweName+"/"+fileName+".class");
        processBuilder.redirectErrorStream(true);
        startProcess(processBuilder);
    }


    public static void main(String args[]) throws IOException, InterruptedException {

        String src_path = "/mnt/c/Users/Valentino/Documents/Universita/Tesi/2Bugginess/Dataset/src";
        String class_path = "/mnt/c/Users/Valentino/Documents/Universita/Tesi/2Bugginess/Dataset/classes" ;

        File file = new File(getAbsolute(Constants.JAVA_SRC));

        File[] cweDir = file.listFiles((FileFilter) FileFilterUtils.directoryFileFilter());

        for(File dir: cweDir){
            File[] files = dir.listFiles();
            System.out.println(files.length);
            for(File f: files) {
                // PMD
                //resultPath = "/mnt/f/Valentino/IdeaProjects/tesiJava/src/main/result/plugins_reports/pmd"+f.getName()+".xml";
                //cmd = ROOT_PATH_PLUGINS+"./run.sh pmd -d ="+src_path+"/"+f.getName() +" -f xml --report-file "+ resultPath +" -R rulesets/java/quickstart.xml";
                System.out.println("****************************PMD****************************\n****************************");
                runCommand(dir.getName(),f.getName().substring(0, f.getName().length()-5),"pmd");

                /*
                // SPOTBUGS
                //String resultPath = "/mnt/c/Users/Valentino/Documents/Universita/Tesi/2Bugginess/Dataset/result/spotbugs/"+f.getName()+".xml";
                //String cmd = ROOT_PATH_PLUGINS+"/spotbugs-4.7.3/bin/spotbugs -textui -bugCategories SECURITY -low -xml="+resultPath+ " -auxclasspath "+class_path+ " -sourcepath "+ src_path+"/"+f.getName() +" " + class_path+"/"+f.getName();
                System.out.println("****************************SPOTBUGS****************************\n****************************");
                runCommand(dir.getName(),f.getName().substring(0, f.getName().length()-5),"spotbugs");

                // FINDSEC
                //resultPath = "/mnt/f/Valentino/IdeaProjects/tesiJava/src/main/result/plugins_reports/findsec"+f.getName()+".xml";
                //cmd = ROOT_PATH_PLUGINS+"/spotbugs-4.7.3/bin/spotbugs -textui -bugCategories SECURITY -pluginList findsecbugs-plugin-1.12.0.jar -low -xml="+resultPath+ " -auxclasspath "+class_path+ " -sourcepath "+ src_path+"/"+f.getName() +" " + class_path+"/"+f.getName();
                System.out.println("****************************FINDSEC****************************\n****************************");
                runCommand(dir.getName(),f.getName().substring(0, f.getName().length()-5),"findsec");

                // JLINT
                //resultPath = "/mnt/f/Valentino/IdeaProjects/tesiJava/src/main/result/plugins_reports/jlint";
                //cmd = ROOT_PATH_PLUGINS+"/jlint +verbose +history "+resultPath+ " -source "+ src_path+"/"+f.getName() +" " + class_path+"/"+f.getName();
                System.out.println("****************************JLINT****************************\n****************************");
                runCommand(dir.getName(),f.getName().substring(0, f.getName().length()-5),"jlint");

                 */
            }
        }
    }
}
