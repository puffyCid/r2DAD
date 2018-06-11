from androguard import misc, session
from androguard.decompiler import decompiler
from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import Analysis
from pathlib import Path
import r2pipe
import sys
import argparse
import os

# Save and open session to/from Radare2 project directory
def r2ProjectName(projectName, sessionName, fileName, sess): 
    project = Path(os.environ['HOME'] + "/.local/share/radare2/projects/" + projectName)
    sessionFile = str(project) +"/" + sessionName
    sessionFile = Path(sessionFile)

    if project.is_dir():
        print("Project exists! -- " + str(project) + "\n")
        if sessionFile.is_file():
            print("Loading session file at " + str(sessionFile) + ", please wait... \n")
            sess = session.Load(str(sessionFile))
            return sess
        else:
                print("No session file found, creating one! Please wait...")
                apk, d, dx = misc.AnalyzeAPK(fileName.decode('utf-8'), session=sess)
                session.Save(sess, str(sessionFile))
                print("Session file created at : " + str(sessionFile) + "\n")

                return sess        
    else:
        print("Radare2 Project does not exist, please save a Radare2 project first")
        exit()

# Decompile user provded class
def decompileClass(className, sess):
    print("Class name is: " + className)
    print("Decompiling whole class...")

    className = className.replace("_", "/")
    dalv = next(sess.get_objects_dex())[1]
    dx = next(sess.get_objects_dex())[2]
    dad = decompiler.DecompilerDAD(dalv, dx)


    classes = dalv.get_classes()
    for c in classes:
        if className in str(c):
            dad.display_all(c)

# Decompile user provided method    
def decompileMethod(className, methodName, sess):
    print("Decompiling whole method...")
    className = className.replace("_", "/")
    dalv = next(sess.get_objects_dex())[1]
    dx = next(sess.get_objects_dex())[2]
    dad = decompiler.DecompilerDAD(dalv, dx)

    classes = dalv.get_classes_names()
    for c in classes:
        if className in c:
            for m in dalv.get_methods_class(c):
                if methodName in str(m):
                    dad.display_source(m)

# Try to detect current method and class
def autoDecompile(dalv,dx,dad,classNames,currentClass, apkMethod):
    apkMethod = apkMethod + "("
    for c in classNames:
            if currentClass in c:
                for m in dalv.get_methods_class(c):
                    if apkMethod in str(m):
                        dad.display_source(m)

def main(projectName, className, methodName):

    if methodName and (not className):
        print('Must provide class name "-c" in order to decompile specific method "-m"')
        exit()

    #Increase recursion limit to save session file
    sys.setrecursionlimit(100000)
    r2 = r2pipe.open()

    fileName = r2.cmd("i~file[1]")
    fileName = fileName.split("/")[2]
    if fileName.split("."):
        sessionName = fileName.split(".")[0]
        sessionName = sessionName+".session"
        sessionFile = Path(sessionName)

    currentClassMethod = r2.cmd("afi.")

    if "_" in currentClassMethod:
        currentClassMethod = str(currentClassMethod).replace("_", "/")

    currentClass = str(currentClassMethod).split(".")[1]
    print("Current class: " + currentClass)

    currentMethod = str(currentClassMethod).split(".")[3]

    apkMethod = currentMethod.split("/")[0]

    if apkMethod == "method":

        currentMethod = str(currentClassMethod).split(".")[4]
        apkMethod = currentMethod.split("(")[0]

    print("    Current Method: " +  apkMethod + "\n")

    sess = misc.get_default_session()

    #Check if project name is passed
    if projectName != None:
        projectSession = r2ProjectName(projectName, sessionName, fileName, sess)

        if className and methodName:
            decompileMethod(className, methodName, projectSession)
            exit()
        if className:
            decompileClass(className, projectSession)
            exit() 

        dalv = next(projectSession.get_objects_dex())[1]
        dx = next(projectSession.get_objects_dex())[2]
        print("Decompiling method " + apkMethod + " in the class" + currentClass)

        dad = decompiler.DecompilerDAD(dalv, dx)

        classNames = dalv.get_classes_names()
        autoDecompile(dalv, dx, dad, classNames, currentClass, apkMethod)
        exit()

    # Check if session file exists    
    if sessionFile.is_file(): 
            
        print("Loading session file, please wait... \n")
        sess = session.Load(sessionName)

        if className and methodName:
            decompileMethod(className, methodName, sess)
            exit()
        if className:
            decompileClass(className, sess)
            exit() 
        

        dalv = next(sess.get_objects_dex())[1]
        dx = next(sess.get_objects_dex())[2]
        dad = decompiler.DecompilerDAD(dalv, dx)

        classNames = dalv.get_classes_names()
        autoDecompile(dalv,dx,dad,classNames, currentClass, apkMethod)

    # Create sesssion file
    else:
        print("No session file found, creating one! Please wait...")
        fileName = fileName.replace("\\n\\x00","")
        fileName = fileName.split("\'")[0]
        apk, d, dx = misc.AnalyzeAPK(fileName, session=sess)
        session.Save(sess, sessionName)

        print("Session file created: " + sessionName)
        print("    Will load session file for future calls... \n")

        if className and methodName:
            decompileMethod(className, methodName, sess)
            exit()

        if className:
            decompileClass(className, sess)
            exit() 

        dalv = next(sess.get_objects_dex())[1]
        dx = next(sess.get_objects_dex())[2]
        dad = decompiler.DecompilerDAD(dalv, dx)

        classNames = dalv.get_classes_names()
        autoDecompile(dalv,dx,dad,classNames,currentClass, apkMethod)

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="r2DAD Decompiler")
    parser.add_argument('-p', dest="project_name", help="Save session with Radare2 Project (Project must already exist!)")
    parser.add_argument('-c', dest="class_name", help="Decompile specific class")
    parser.add_argument('-m', dest="method_name", help="Decompile specific method (must be used with -c)")
    args = parser.parse_args()

    main(args.project_name, args.class_name, args.method_name)
