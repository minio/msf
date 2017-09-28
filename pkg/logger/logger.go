/*
 * Federator, (C) 2017 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package logger

import (
	"fmt"
	"path"
	"runtime"
	"strings"

	"github.com/Sirupsen/logrus"
)

var log = logrus.New()

func logIf(level logrus.Level, source string, err error, msg string, data ...interface{}) {
	fields := logrus.Fields{
		"source": source,
		"cause":  err.Error(),
	}

	switch level {
	case logrus.PanicLevel:
		log.WithFields(fields).Panicf(msg, data...)
	case logrus.FatalLevel:
		log.WithFields(fields).Fatalf(msg, data...)
	case logrus.ErrorLevel:
		log.WithFields(fields).Errorf(msg, data...)
	case logrus.WarnLevel:
		log.WithFields(fields).Warnf(msg, data...)
	case logrus.InfoLevel:
		log.WithFields(fields).Infof(msg, data...)
	default:
		log.WithFields(fields).Debugf(msg, data...)
	}
}

func getSource() string {
	var funcName string
	pc, filename, lineNum, ok := runtime.Caller(2)
	if ok {
		filename = path.Base(filename)
		funcName = strings.TrimPrefix(runtime.FuncForPC(pc).Name(), "github.com/minio/federator.")
	} else {
		filename = "<unknown>"
		lineNum = 0
	}

	return fmt.Sprintf("[%s:%d:%s()]", filename, lineNum, funcName)
}

// ErrorIf - logs if err is non-nil.
func ErrorIf(err error, msg string, data ...interface{}) {
	logIf(logrus.ErrorLevel, getSource(), err, msg, data...)
}

// FatalIf - logs if err is non-nil.
func FatalIf(err error, msg string, data ...interface{}) {
	logIf(logrus.FatalLevel, getSource(), err, msg, data...)
}
