#!/usr/bin/python
# -*- coding: UTF-8 -*-

import os

# IDA Path

IDA32_DIR = "your_path/IDA_Pro64/IDA_Pro64/idaq"
IDA64_DIR = "your_path/IDA_Pro64/IDA_Pro64/idaq64"

ROOT_DIR = os.path.dirname(os.path.realpath(__file__)) #  The path of the current file
print "ROOT_DIR:",ROOT_DIR

CODE_DIR = ROOT_DIR
O_DIR = ROOT_DIR+ os.sep + "0_Libs"                  #  The root path of All the binary file
print "O_DIR:",O_DIR
IDB_DIR = ROOT_DIR+ os.sep + "0_Libs"                #  The root path of All the idb file
FEA_DIR = ROOT_DIR+ os.sep + "1_Features"            #  The root path of  the feature file
DATASET_DIR = ROOT_DIR+ os.sep + "2_Dataset"
TFRECORD_GEMINI_DIR = ROOT_DIR+ os.sep + "3_TFRecord"+  os.sep + "Gemini"
TFRECORD_VULSEEKER_DIR = ROOT_DIR+ os.sep + "3_TFRecord" + os.sep + "VulSeeker"
MODEL_GEMINI_DIR = ROOT_DIR+ os.sep + "4_Model" + os.sep + "Gemini"
MODEL_VULSEEKER_DIR = ROOT_DIR+ os.sep + "4_Model" + os.sep + "VulSeeker"
CVE_FEATURE_DIR = ROOT_DIR+ os.sep + "5_CVE_Feature"
SEARCH_GEMINI_TFRECORD_DIR = ROOT_DIR+ os.sep + "6_Search_TFRecord" + os.sep + "Gemini"
SEARCH_VULSEEKER_TFRECORD_DIR = ROOT_DIR+ os.sep + "6_Search_TFRecord" + os.sep + "VulSeeker"
SEARCH_RESULT_GEMINI_DIR = ROOT_DIR+ os.sep + "7_Search_Result" + os.sep + "Gemini"
SEARCH_RESULT_VULSEEKER_DIR = ROOT_DIR+ os.sep + "7_Search_Result" + os.sep + "VulSeeker"

# if convert all binary files into disassembly files
STEP1_GEN_IDB_FILE = False
#STEP1_PORGRAM_ARR=["openssl"]#"openssl","coreutils","busybox","CVE-2015-1791"
STEP1_PORGRAM_ARR=["wget"]
# if extract feature file
STEP2_GEN_FEA = True
STEP2_PORGRAM_ARR=["wget"]  #  all the project name"openssl",,"busybox","coreutils","CVE-2015-1791"
STEP2_REMOVE_DUP = True
#STEP2_PORGRAM_ARR=["wget"]  #  all the project name
STEP2_CVE_OPENSSL_FUN_LIST = {'ssl3_get_new_session_ticket':'CVE-2015-1791', 'OBJ_obj2txt':'CVE-2014-3508'}

# #  傅滢的！！！=======
# STEP1_PORGRAM_ARR=["openssl"]
# # STEP1_PORGRAM_ARR=["openssl","CVE-2015-1791","busybox","coreutils"]
#
# # if extract feature file
# STEP2_GEN_FEA = True
# STEP2_PORGRAM_ARR=["openssl"]  #  all the project name

# if train train dataset
STEP3_GEN_DATASET = False
STEP3_PORGRAM_ARR = ["openssl"]#"openssl","coreutils","busybox",
TRAIN_DATASET_NUM = 50000

# if train VulSeeker TFrecord
STEP4_GEN_TFRECORD_GEMINI = False
STEP4_GEN_TFRECORD_VUL = False

STEP5_TRAIN_GEMINI_MODEL = False
STEP5_IF_RESTORE_GEMINI_MODEL = True
STEP5_GEMINI_MODEL_TO_RESTORE = "gemini-model_50000_23.ckpt"
STEP5_TRAIN_VULSEEKER_MODEL = False
SETP5_IF_RESTORE_VULSEEKER_MODEL = False
STEP5_VULSEEKER_MODEL_TO_RESTORE = ""

STEP6_CVE_FUN_LIST = {'CVE-2017-6508':'url_parse'}
STEP6_GEN_SEARCH_GEMINI_TFRECORD = False
STEP6_GEN_SEARCH_VULSEEKER_TFRECORD = False
STEP6_SEARCH_PROGRAM_ARR = ["wget"]

STEP7_IF_SEARCH_GEMINI=False
STEP7_SEARCH_GEMINI_MODEL="gemini-model_50000_23.ckpt"
STEP7_IF_SEARCH_VULSEEKER=True
STEP7_SEARCH_VULSEEKER_MODEL="vulseeker-model_final.ckpt"
