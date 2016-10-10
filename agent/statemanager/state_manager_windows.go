// +build windows

// Copyright 2014-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package statemanager

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/cihub/seelog"

	"golang.org/x/sys/windows/registry"
)

const (
	ecsDataFileRootKey   = registry.LOCAL_MACHINE
	ecsDataFileKeyPath   = `SOFTWARE\Amazon\ECS Agent\State File`
	ecsDataFileValueName = "path"
)

/*
On Windows, the basic approach for attempting to ensure that the state file is
written out correctly relies on the Windows Registry and documented behavior of
the Win32 API.

On each save, the agent creates a new file where it writes out the json object.
Once the file is written, it gets flushed to disk using the Win32
FlushFileBuffers API.  After the file is flushed to disk, a registry key is
updated to indicate the new file name.  Finally, the old file retrieved from the
registry key is deleted.

On each load, the agent reads a well-known registry key to find the name of the
file to load.
*/

func (manager *basicStateManager) readFile() ([]byte, error) {
	manager.savingLock.Lock()
	defer manager.savingLock.Unlock()
	path, err := manager.getPath()
	if err != nil {
		if err == registry.ErrNotExist {
			// Happens on the first run; not a real error
			return nil, nil
		}
		return nil, err
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			// Happens every first run; not a real error
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()
	return ioutil.ReadAll(file)
}

func (manager *basicStateManager) getPath() (string, error) {
	key, err := registry.OpenKey(ecsDataFileRootKey, ecsDataFileKeyPath, registry.READ)
	if err != nil {
		return "", err
	}
	defer key.Close()
	val, _, err := key.GetStringValue(ecsDataFileValueName)
	if err != nil {
		return "", err
	}
	return val, nil
}

func (manager *basicStateManager) writeFile(data []byte) error {
	oldFile, err := manager.getPath()
	if err != nil {
		if err != registry.ErrNotExist {
			return err
		}
		oldFile = ""
	}
	dataFile, err := ioutil.TempFile(manager.statePath, ecsDataFile)
	if err != nil {
		seelog.Errorf("Error saving state; could not create file to save state: %v", err)
		return err
	}
	defer dataFile.Close()
	_, err = dataFile.Write(data)
	if err != nil {
		seelog.Errorf("Error saving state; could not write to file to save state: %s %v ", dataFile.Name(), err)
		return err
	}
	err = dataFile.Sync() // this calls FlushFileBuffers, see https://golang.org/src/syscall/syscall_windows.go#L523
	if err != nil {
		seelog.Errorf("Error saving state; could not sync file to save state: %s %v", dataFile.Name(), err)
		return err
	}
	err = dataFile.Close()
	if err != nil {
		seelog.Errorf("Error saving state; could not close file to save state: %s %v", dataFile.Name(), err)
	}
	err = manager.savePath(dataFile.Name())
	if err != nil {
		seelog.Errorf("Failed to save the data file path: %v", err)
		return err
	}
	err = os.Remove(oldFile)
	if err != nil {
		seelog.Errorf("Error removing old file %s; err %v", oldFile, err)
	}
	return err
}

func (manager *basicStateManager) savePath(path string) error {
	key, existed, err := registry.CreateKey(ecsDataFileRootKey, ecsDataFileKeyPath, registry.SET_VALUE|registry.CREATE_SUB_KEY)
	if err != nil {
		seelog.Error(err)
		return err
	}
	defer key.Close()
	if !existed {
		seelog.Infof(`Created new registry key: %s\%s`, ecsDataFileRootKey, ecsDataFileKeyPath)
	}
	return key.SetStringValue(ecsDataFileValueName, path)
}
