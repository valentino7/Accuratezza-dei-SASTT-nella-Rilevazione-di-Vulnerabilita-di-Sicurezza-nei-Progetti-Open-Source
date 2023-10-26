package utils;

public class Constants {

    // Directory contenente i progetti divisi per fix e parent commit nomeprogetto+fix/parent commit prodotto dallo script CreateFixParentDir.java
    public static final String PATH_PROJECT_ROOT = "src\\main\\java\\resources\\ProgettiFixParentCommit\\";

    // Repositories git dei progetti scaricati dall script python download_project.py
    public static final String PATH_PROJECT_REPOSITORIES = "src\\main\\java\\resources\\Repositories\\";

    ////////////////////////////////////////PATH DA MODIFICARE QUANDO SI RUNNA RunnerTools.java/////////////////////////////////////////////////////////////////////////////
    // Directory contenente gli eseguibili dei tool: spotbugs e findsec, jlint, pmd, snyk e vcg.
    public static final String BIN_TOOLS = "/mnt/c/Users/Valentino/Documents/Universita/Tesi/Tesi/Pacchetto_di_replicabilita/RQ2/plugins";
    public static final String JAVA_SRC_RUNNER_TOOLS = "/mnt/c/Users/Valentino/Documents/Universita/Tesi/Tesi/SASTT-Accuracy-in-Finding-Security-Vulnerabilities-in-OSS/RQ2/RQ2JavaProject/src/main/java/resources/ClassiJava/src/";
    public static final String PMD_PATH_REPORT_RESULT_MNT = "mnt/c/Users/Valentino/Documents/Universita/Tesi/Tesi/SASTT-Accuracy-in-Finding-Security-Vulnerabilities-in-OSS/RQ2/RQ2JavaProject/src/main/java/resources/ToolReports/pmd/";

    public static final String JAVA_CLASS_RUNNER_TOOLS = "/mnt/c/Users/Valentino/Documents/Universita/Tesi/Tesi/RQ3/tesiJava_server/src/main/java/resources/ClassiJava/classes";
    public static final String REPORT_RESULTS_RUNNER_TOOLS = "/mnt/c/Users/Valentino/Documents/Universita/Tesi/Tesi/RQ3/tesiJava_server/src/main/java/resources/ToolReports/";



    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Vulas db
    public static final String PATH_VULAS_DB = "src\\main\\java\\resources\\vulas_db_without_invalid_cve.csv";

    // Risultato dello script python create_mapping_cve_cwe.py.py
    public static final String PATH_MAPPING_CVE = "src\\main\\java\\resources\\mapping_cve_cwe.csv";
    public static final String FILTER_PATH_MAPPING_CVE = "src\\main\\java\\resources\\filter_mapping_cve_cwe.csv";

    // Directory contenente le classi java dei progetti e alcuni .class create per il vecchio task non più utile
    public static final String JAVA_SRC = "src\\main\\java\\resources\\ClassiJava\\src";

    // Intermediate result prodotto da FillMethodInfoInCommit.java
    public static final String INTERMEDIATE_PATH_RESULT = "src\\main\\java\\resources\\intermediate_result.csv";
    // Statistiche prodotte sui cwe da FillMethodInfoInCommit.java
    public static final String CWE_LIST_BY_JAVA_CLASS = "src\\main\\java\\resources\\analisi\\listaCWEConClassiJava.csv";
    public static final String VULAS_ROW_WITH__JAVA_CLASS_IN_COMMIT = "src\\main\\java\\resources\\analisi\\elementiVulasConClassiJava.csv";


    // Input per RunSnykCommand.java prodotto da CreateMappingParentSonCommit.java
    public static final String MAPPING_FIX_PARENT_COMMIT = "src\\main\\java\\resources\\mappingFixCommitParentCommit.csv";

    //Path dei report generati dai tool
    public static final String REPORT_RESULTS = "src\\main\\java\\resources\\ToolReports\\";




    //////////////////////////////////PATH per script di test e analisi//////////////////////////////////////////////////////////
    // CountCerProject.java
    // Cwe rilevati da snyk
    public static final String ROOT_ANALISI = "src\\main\\java\\resources\\analisi\\";



    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //public static final String PATH_COMPILE = "F:\\Valentino\\IdeaProjects\\tesiJava\\src\\main\\java\resources\\project_command_version.csv";
    public static final String PATH_COMPILE = "src\\main\\result\\Compilati\\statsCompileResultWithoutComment.csv";

    //Risultato dello script ParsingTool.java
    public static final String ROOT_PATH_PARSING_REPORT = "src\\main\\java\\resources\\ParsingToolResult\\";
    public static final String PATH_VCG_PARSING_REPORT = "src\\main\\java\\resources\\ParsingToolResult\\fileVCG.csv";
    public static final String PATH_PMD_PARSING_REPORT = "src\\main\\java\\resources\\ParsingToolResult\\filePMD.csv";
    public static final String PATH_SNYK_PARSING_REPORT = "src\\main\\java\\resources\\ParsingToolResult\\fileSnyk.csv";
    public static final String MAPPING_CWE_PMD = "src\\main\\java\\resources\\Mapping\\CweMappingPmd.csv";
    public static final String MAPPING_CWE_SNYK = "src\\main\\java\\resources\\Mapping\\Snyk.xml";

    // CreateFinalDataset.java
    public static final String PATH_FINAL_RESULT = "src\\main\\java\\resources\\FinalResult\\";
    public static final String PATH_MAPPING_PATH = "src\\main\\java\\resources\\MAP_path.csv";









    ////////////////////////////////////////Path tesi con tool che utilizzano i compilati///////////////////////////////////////
    public static final String PATH_FINDSEC_RESULT = "src\\main\\java\\resources\\ParsingToolResult\\fileFindSecBugs.csv";
    public static final String FINDSEC_INPUT_1 = "src\\main\\java\\resources\\TesiProgettiCompilazione\\findsecbugsCWEMappings.xml";
    public static final String FINDSEC_INPUT_2 = "src\\main\\java\\resources\\TesiProgettiCompilazione\\findbugsCWEMappings.xml";
    public static final String PATH_SPOTBUGS_RESULT = "src\\main\\java\\resources\\ParsingToolResult\\fileSpotBugs.csv";
    public static final String PATH_JLINT_RESULT = "src\\main\\java\\resources\\ParsingToolResult\\fileJLint.csv";
    public static final String MAPPING_CWE_JLINT = "src\\main\\java\\resources\\TesiProgettiCompilazione\\jlintCWEMappings.xml";

    public static final String COMPILATOR= "ant";
    public static final String STATS_RESULT = "src\\main\\result\\Compilati\\statsCompileResult.csv";
    public static final String SOURCE_JDK_RESULT = "src\\main\\result\\Compilati\\statsSourceJDKResultNOcompilable.csv";
    public static final String JAVA_CLASS = "src\\main\\java\\resources\\ClassiJava\\classes";


}
