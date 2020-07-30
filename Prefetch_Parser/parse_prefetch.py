#
# Parse Prefetch
#
# Copyright 2020 Mark McKinnon.
# Contact: mark <dot> mckinnon <at> gmail <dot> com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import pyscca
import os
import sys
from Database import SQLiteDb

columnNames = "prefetch_File_Name, actual_File_Name, Number_time_file_run, Embeded_date_Time_Unix_1, " + \
              "Embeded_date_Time_Unix_2, Embeded_date_Time_Unix_3, Embeded_date_Time_Unix_4, Embeded_date_Time_Unix_5, " + \
              "Embeded_date_Time_Unix_6, Embeded_date_Time_Unix_7, Embeded_date_Time_Unix_8, file_path"
tableName = "prefetch_file_info"
tableColumns = "prefetch_File_Name text, actual_File_Name text, file_path text, Number_time_file_run int, Embeded_date_Time_Unix_1 int, " + \
                "Embeded_date_Time_Unix_2 int, Embeded_date_Time_Unix_3 int, Embeded_date_Time_Unix_4 int, Embeded_date_Time_Unix_5 int, " + \
                "Embeded_date_Time_Unix_6 int, Embeded_date_Time_Unix_7 int, Embeded_date_Time_Unix_8 int"
sqlBindVals = "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?"

volumeTabName = "volume_Information"
volumeColumnNames = "prefetch_file_name text, device_path text, creation_Time text, creation_time_filetime int, serial_number text"
volumeColumns = "prefetch_file_name, device_path, creation_Time, creation_time_filetime, serial_number"
volumeBindVals = "?, ?, ?, ?, ?"

fileMetricsTabName = "file_metrics"
fileMetricsColumnNames = "Prefetch_file_name text, file_metric_number int, file_metric_path text, file_metric_name text"
fileMetricsColumns = "Prefetch_file_name, file_metric_number, file_metric_path, file_metric_name"
fileMetricsBindVals = "?, ?, ?, ?"

fileTabName = "file_names"
fileColumnNames = "Prefetch_file_name text, file_path text, file_name text"
fileColumns = "Prefetch_file_name, file_path, file_name"
fileBindVals = "?, ?, ?"

args = sys.argv[1:]
prefetchDirectory = args[0]
SQLiteDbName = args[1]
print ('Prefetch Directory is ', str(prefetchDirectory))
print ('DB file is ', SQLiteDbName)
SQLitedb = SQLiteDb()
SQLitedb.RemoveDB_File(SQLiteDbName)
SQLitedb.Open(SQLiteDbName)
SQLitedb.CreateTable(tableName, tableColumns)
SQLitedb.CreateTable(fileMetricsTabName, fileMetricsColumnNames)
SQLitedb.CreateTable(volumeTabName, volumeColumnNames)
SQLitedb.CreateTable(fileTabName, fileColumnNames)

for root, dirs, files in os.walk(prefetchDirectory):
#    print ("root = > " +  str(root))
#    print ("dirs = > " + str(dirs))
#    print ("files = > " + str(files))
    for file in files:
        if ".pf" in file:
            prefetchRecord = []
            try:
                scca = pyscca.open(os.path.join(root, file))
                #print("File Name is ==> " + file)
                prefetchRecord.append(file)
                prefetchRecord.append(scca.get_executable_filename())
                prefetchExecutableFileName = scca.get_executable_filename()
                prefetchExecutableFilePath = ""
                prefetchExecutablePath = ""
                #print ("File Name ==> " + scca.get_executable_filename())
                #print ("File Name ==> " + scca.get_filename())
                try:
                    if scca.get_run_count() is None:
                        prefetchRecord.append(0)
                    else:
                        prefetchRecord.append(scca.get_run_count())
                except:
                    prefetchRecord.append(0)
                #print ("Run Count ==> " + str(scca.get_run_count()))
                for i in range(8):
                    try:
                        if scca.get_last_run_time_as_integer(i) is None or scca.get_last_run_time_as_integer(i) == 0:
                            prefetchRecord.append(0)
                        else:
                            prefetchRecord.append(int(str(scca.get_last_run_time_as_integer(i))[:11]) - 11644473600)
                        #print ("Last Run Tine ==> " + str(scca.get_last_run_time_as_integer(i)))
                    except:
                        prefetchRecord.append(0)
                        #print ("Last Run time ==> 0")
                #print (scca.get_number_of_file_metrics_entries)
                #prefetchRecord.append(scca.get_prefetch_hash)
                fileMetricEntries = scca.get_number_of_file_metrics_entries()
                numberVolumes = scca.get_number_of_volumes()
                numberFileNames = scca.get_number_of_filenames()
                for i in range(fileMetricEntries):
                    fileMetricList = []
                    fileMetricEntry = scca.get_file_metrics_entry(i)
                    fileMetricList.append(file)
                    fileMetricList.append(i)

                    newPath = fileMetricEntry.get_filename().replace('\\','/')
                    (path, fileName) = os.path.split(newPath)
#                    (path, fileName) = os.path.split(fileMetricEntry.get_filename())
                    fileMetricList.append(path)
                    fileMetricList.append(fileName)
                    SQLitedb.InsertBindValues(fileMetricsTabName, fileMetricsColumns, fileMetricsBindVals, fileMetricList)
#                    print (fileName + " <<>> " + prefetchExecutableFileName)
                    if fileName == prefetchExecutableFileName:
                       prefetchExecutableFilePath = path
                       #print (path)
                for i in range(numberVolumes):
                    volumeList = []
                    volumeEntry = scca.get_volume_information(i)
                    volumeList.append(file)
                    devicePath = volumeEntry.get_device_path().replace('\\','/')
                    volumeList.append(devicePath)
                    volumeList.append(volumeEntry.get_creation_time())
                    volumeList.append(volumeEntry.get_creation_time_as_integer())
                    volumeList.append(volumeEntry.get_serial_number())
                    SQLitedb.InsertBindValues(volumeTabName, volumeColumns, volumeBindVals, volumeList)
#                    print (volumeList)
                    if (devicePath in prefetchExecutableFilePath):
                        prefetchExecutablePath = prefetchExecutableFilePath.replace(devicePath, '')
                prefetchRecord.append(prefetchExecutablePath)
                for i in range(numberFileNames):
                    fileNameList = []
                    fileNameList.append(file)
                    (path, fileName) = os.path.split(scca.get_filename(i).replace('\\','/'))
                    fileNameList.append(path)
                    fileNameList.append(fileName)
                    SQLitedb.InsertBindValues(fileTabName, fileColumns, fileBindVals, fileNameList)
                SQLitedb.InsertBindValues(tableName, columnNames, sqlBindVals, prefetchRecord)
                scca.close()
            except Exception as e:
                print (str(e) + " == " + str(e.args))
                print ("Error in prefetch file " + file)

SQLitedb.Close()  

