/*
* Copyright 2010-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License").
* You may not use this file except in compliance with the License.
* A copy of the License is located at
*
*  http://aws.amazon.com/apache2.0
*
* or in the "license" file accompanying this file. This file is distributed
* on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
* express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/
#pragma once
#include <aws/machinelearning/MachineLearning_EXPORTS.h>
#include <aws/core/utils/memory/stl/AWSString.h>

namespace Aws
{
namespace Utils
{
namespace Json
{
  class JsonValue;
} // namespace Json
} // namespace Utils
namespace MachineLearning
{
namespace Model
{

  /**
   * <p> Describes the data specification of a <code>DataSource</code>.</p>
   */
  class AWS_MACHINELEARNING_API S3DataSpec
  {
  public:
    S3DataSpec();
    S3DataSpec(const Aws::Utils::Json::JsonValue& jsonValue);
    S3DataSpec& operator=(const Aws::Utils::Json::JsonValue& jsonValue);
    Aws::Utils::Json::JsonValue Jsonize() const;

    /**
     * <p>The location of the data file(s) used by a <code>DataSource</code>. The URI
     * specifies a data file or an Amazon Simple Storage Service (Amazon S3) directory
     * or bucket containing data files.</p>
     */
    inline const Aws::String& GetDataLocationS3() const{ return m_dataLocationS3; }

    /**
     * <p>The location of the data file(s) used by a <code>DataSource</code>. The URI
     * specifies a data file or an Amazon Simple Storage Service (Amazon S3) directory
     * or bucket containing data files.</p>
     */
    inline void SetDataLocationS3(const Aws::String& value) { m_dataLocationS3HasBeenSet = true; m_dataLocationS3 = value; }

    /**
     * <p>The location of the data file(s) used by a <code>DataSource</code>. The URI
     * specifies a data file or an Amazon Simple Storage Service (Amazon S3) directory
     * or bucket containing data files.</p>
     */
    inline void SetDataLocationS3(Aws::String&& value) { m_dataLocationS3HasBeenSet = true; m_dataLocationS3 = value; }

    /**
     * <p>The location of the data file(s) used by a <code>DataSource</code>. The URI
     * specifies a data file or an Amazon Simple Storage Service (Amazon S3) directory
     * or bucket containing data files.</p>
     */
    inline void SetDataLocationS3(const char* value) { m_dataLocationS3HasBeenSet = true; m_dataLocationS3.assign(value); }

    /**
     * <p>The location of the data file(s) used by a <code>DataSource</code>. The URI
     * specifies a data file or an Amazon Simple Storage Service (Amazon S3) directory
     * or bucket containing data files.</p>
     */
    inline S3DataSpec& WithDataLocationS3(const Aws::String& value) { SetDataLocationS3(value); return *this;}

    /**
     * <p>The location of the data file(s) used by a <code>DataSource</code>. The URI
     * specifies a data file or an Amazon Simple Storage Service (Amazon S3) directory
     * or bucket containing data files.</p>
     */
    inline S3DataSpec& WithDataLocationS3(Aws::String&& value) { SetDataLocationS3(value); return *this;}

    /**
     * <p>The location of the data file(s) used by a <code>DataSource</code>. The URI
     * specifies a data file or an Amazon Simple Storage Service (Amazon S3) directory
     * or bucket containing data files.</p>
     */
    inline S3DataSpec& WithDataLocationS3(const char* value) { SetDataLocationS3(value); return *this;}

    /**
     * <p> Describes the splitting requirement of a <code>Datasource</code>.</p>
     */
    inline const Aws::String& GetDataRearrangement() const{ return m_dataRearrangement; }

    /**
     * <p> Describes the splitting requirement of a <code>Datasource</code>.</p>
     */
    inline void SetDataRearrangement(const Aws::String& value) { m_dataRearrangementHasBeenSet = true; m_dataRearrangement = value; }

    /**
     * <p> Describes the splitting requirement of a <code>Datasource</code>.</p>
     */
    inline void SetDataRearrangement(Aws::String&& value) { m_dataRearrangementHasBeenSet = true; m_dataRearrangement = value; }

    /**
     * <p> Describes the splitting requirement of a <code>Datasource</code>.</p>
     */
    inline void SetDataRearrangement(const char* value) { m_dataRearrangementHasBeenSet = true; m_dataRearrangement.assign(value); }

    /**
     * <p> Describes the splitting requirement of a <code>Datasource</code>.</p>
     */
    inline S3DataSpec& WithDataRearrangement(const Aws::String& value) { SetDataRearrangement(value); return *this;}

    /**
     * <p> Describes the splitting requirement of a <code>Datasource</code>.</p>
     */
    inline S3DataSpec& WithDataRearrangement(Aws::String&& value) { SetDataRearrangement(value); return *this;}

    /**
     * <p> Describes the splitting requirement of a <code>Datasource</code>.</p>
     */
    inline S3DataSpec& WithDataRearrangement(const char* value) { SetDataRearrangement(value); return *this;}

    /**
     * <p> A JSON string that represents the schema for an Amazon S3
     * <code>DataSource</code>. The <code>DataSchema</code> defines the structure of
     * the observation data in the data file(s) referenced in the
     * <code>DataSource</code>.</p> <p>Define your <code>DataSchema</code> as a series
     * of key-value pairs. <code>attributes</code> and
     * <code>excludedVariableNames</code> have an array of key-value pairs for their
     * value. Use the following format to define your <code>DataSchema</code>.</p> <p>{
     * "version": "1.0",</p> <p> "recordAnnotationFieldName": "F1",</p> <p>
     * "recordWeightFieldName": "F2",</p> <p> "targetFieldName": "F3",</p> <p>
     * "dataFormat": "CSV",</p> <p> "dataFileContainsHeader": true,</p> <p>
     * "attributes": [</p> <p> { "fieldName": "F1", "fieldType": "TEXT" }, {
     * "fieldName": "F2", "fieldType": "NUMERIC" }, { "fieldName": "F3", "fieldType":
     * "CATEGORICAL" }, { "fieldName": "F4", "fieldType": "NUMERIC" }, { "fieldName":
     * "F5", "fieldType": "CATEGORICAL" }, { "fieldName": "F6", "fieldType": "TEXT" },
     * { "fieldName": "F7", "fieldType": "WEIGHTED_INT_SEQUENCE" }, { "fieldName":
     * "F8", "fieldType": "WEIGHTED_STRING_SEQUENCE" } ],</p> <p>
     * "excludedVariableNames": [ "F6" ] } </p> <?oxy_insert_end>
     */
    inline const Aws::String& GetDataSchema() const{ return m_dataSchema; }

    /**
     * <p> A JSON string that represents the schema for an Amazon S3
     * <code>DataSource</code>. The <code>DataSchema</code> defines the structure of
     * the observation data in the data file(s) referenced in the
     * <code>DataSource</code>.</p> <p>Define your <code>DataSchema</code> as a series
     * of key-value pairs. <code>attributes</code> and
     * <code>excludedVariableNames</code> have an array of key-value pairs for their
     * value. Use the following format to define your <code>DataSchema</code>.</p> <p>{
     * "version": "1.0",</p> <p> "recordAnnotationFieldName": "F1",</p> <p>
     * "recordWeightFieldName": "F2",</p> <p> "targetFieldName": "F3",</p> <p>
     * "dataFormat": "CSV",</p> <p> "dataFileContainsHeader": true,</p> <p>
     * "attributes": [</p> <p> { "fieldName": "F1", "fieldType": "TEXT" }, {
     * "fieldName": "F2", "fieldType": "NUMERIC" }, { "fieldName": "F3", "fieldType":
     * "CATEGORICAL" }, { "fieldName": "F4", "fieldType": "NUMERIC" }, { "fieldName":
     * "F5", "fieldType": "CATEGORICAL" }, { "fieldName": "F6", "fieldType": "TEXT" },
     * { "fieldName": "F7", "fieldType": "WEIGHTED_INT_SEQUENCE" }, { "fieldName":
     * "F8", "fieldType": "WEIGHTED_STRING_SEQUENCE" } ],</p> <p>
     * "excludedVariableNames": [ "F6" ] } </p> <?oxy_insert_end>
     */
    inline void SetDataSchema(const Aws::String& value) { m_dataSchemaHasBeenSet = true; m_dataSchema = value; }

    /**
     * <p> A JSON string that represents the schema for an Amazon S3
     * <code>DataSource</code>. The <code>DataSchema</code> defines the structure of
     * the observation data in the data file(s) referenced in the
     * <code>DataSource</code>.</p> <p>Define your <code>DataSchema</code> as a series
     * of key-value pairs. <code>attributes</code> and
     * <code>excludedVariableNames</code> have an array of key-value pairs for their
     * value. Use the following format to define your <code>DataSchema</code>.</p> <p>{
     * "version": "1.0",</p> <p> "recordAnnotationFieldName": "F1",</p> <p>
     * "recordWeightFieldName": "F2",</p> <p> "targetFieldName": "F3",</p> <p>
     * "dataFormat": "CSV",</p> <p> "dataFileContainsHeader": true,</p> <p>
     * "attributes": [</p> <p> { "fieldName": "F1", "fieldType": "TEXT" }, {
     * "fieldName": "F2", "fieldType": "NUMERIC" }, { "fieldName": "F3", "fieldType":
     * "CATEGORICAL" }, { "fieldName": "F4", "fieldType": "NUMERIC" }, { "fieldName":
     * "F5", "fieldType": "CATEGORICAL" }, { "fieldName": "F6", "fieldType": "TEXT" },
     * { "fieldName": "F7", "fieldType": "WEIGHTED_INT_SEQUENCE" }, { "fieldName":
     * "F8", "fieldType": "WEIGHTED_STRING_SEQUENCE" } ],</p> <p>
     * "excludedVariableNames": [ "F6" ] } </p> <?oxy_insert_end>
     */
    inline void SetDataSchema(Aws::String&& value) { m_dataSchemaHasBeenSet = true; m_dataSchema = value; }

    /**
     * <p> A JSON string that represents the schema for an Amazon S3
     * <code>DataSource</code>. The <code>DataSchema</code> defines the structure of
     * the observation data in the data file(s) referenced in the
     * <code>DataSource</code>.</p> <p>Define your <code>DataSchema</code> as a series
     * of key-value pairs. <code>attributes</code> and
     * <code>excludedVariableNames</code> have an array of key-value pairs for their
     * value. Use the following format to define your <code>DataSchema</code>.</p> <p>{
     * "version": "1.0",</p> <p> "recordAnnotationFieldName": "F1",</p> <p>
     * "recordWeightFieldName": "F2",</p> <p> "targetFieldName": "F3",</p> <p>
     * "dataFormat": "CSV",</p> <p> "dataFileContainsHeader": true,</p> <p>
     * "attributes": [</p> <p> { "fieldName": "F1", "fieldType": "TEXT" }, {
     * "fieldName": "F2", "fieldType": "NUMERIC" }, { "fieldName": "F3", "fieldType":
     * "CATEGORICAL" }, { "fieldName": "F4", "fieldType": "NUMERIC" }, { "fieldName":
     * "F5", "fieldType": "CATEGORICAL" }, { "fieldName": "F6", "fieldType": "TEXT" },
     * { "fieldName": "F7", "fieldType": "WEIGHTED_INT_SEQUENCE" }, { "fieldName":
     * "F8", "fieldType": "WEIGHTED_STRING_SEQUENCE" } ],</p> <p>
     * "excludedVariableNames": [ "F6" ] } </p> <?oxy_insert_end>
     */
    inline void SetDataSchema(const char* value) { m_dataSchemaHasBeenSet = true; m_dataSchema.assign(value); }

    /**
     * <p> A JSON string that represents the schema for an Amazon S3
     * <code>DataSource</code>. The <code>DataSchema</code> defines the structure of
     * the observation data in the data file(s) referenced in the
     * <code>DataSource</code>.</p> <p>Define your <code>DataSchema</code> as a series
     * of key-value pairs. <code>attributes</code> and
     * <code>excludedVariableNames</code> have an array of key-value pairs for their
     * value. Use the following format to define your <code>DataSchema</code>.</p> <p>{
     * "version": "1.0",</p> <p> "recordAnnotationFieldName": "F1",</p> <p>
     * "recordWeightFieldName": "F2",</p> <p> "targetFieldName": "F3",</p> <p>
     * "dataFormat": "CSV",</p> <p> "dataFileContainsHeader": true,</p> <p>
     * "attributes": [</p> <p> { "fieldName": "F1", "fieldType": "TEXT" }, {
     * "fieldName": "F2", "fieldType": "NUMERIC" }, { "fieldName": "F3", "fieldType":
     * "CATEGORICAL" }, { "fieldName": "F4", "fieldType": "NUMERIC" }, { "fieldName":
     * "F5", "fieldType": "CATEGORICAL" }, { "fieldName": "F6", "fieldType": "TEXT" },
     * { "fieldName": "F7", "fieldType": "WEIGHTED_INT_SEQUENCE" }, { "fieldName":
     * "F8", "fieldType": "WEIGHTED_STRING_SEQUENCE" } ],</p> <p>
     * "excludedVariableNames": [ "F6" ] } </p> <?oxy_insert_end>
     */
    inline S3DataSpec& WithDataSchema(const Aws::String& value) { SetDataSchema(value); return *this;}

    /**
     * <p> A JSON string that represents the schema for an Amazon S3
     * <code>DataSource</code>. The <code>DataSchema</code> defines the structure of
     * the observation data in the data file(s) referenced in the
     * <code>DataSource</code>.</p> <p>Define your <code>DataSchema</code> as a series
     * of key-value pairs. <code>attributes</code> and
     * <code>excludedVariableNames</code> have an array of key-value pairs for their
     * value. Use the following format to define your <code>DataSchema</code>.</p> <p>{
     * "version": "1.0",</p> <p> "recordAnnotationFieldName": "F1",</p> <p>
     * "recordWeightFieldName": "F2",</p> <p> "targetFieldName": "F3",</p> <p>
     * "dataFormat": "CSV",</p> <p> "dataFileContainsHeader": true,</p> <p>
     * "attributes": [</p> <p> { "fieldName": "F1", "fieldType": "TEXT" }, {
     * "fieldName": "F2", "fieldType": "NUMERIC" }, { "fieldName": "F3", "fieldType":
     * "CATEGORICAL" }, { "fieldName": "F4", "fieldType": "NUMERIC" }, { "fieldName":
     * "F5", "fieldType": "CATEGORICAL" }, { "fieldName": "F6", "fieldType": "TEXT" },
     * { "fieldName": "F7", "fieldType": "WEIGHTED_INT_SEQUENCE" }, { "fieldName":
     * "F8", "fieldType": "WEIGHTED_STRING_SEQUENCE" } ],</p> <p>
     * "excludedVariableNames": [ "F6" ] } </p> <?oxy_insert_end>
     */
    inline S3DataSpec& WithDataSchema(Aws::String&& value) { SetDataSchema(value); return *this;}

    /**
     * <p> A JSON string that represents the schema for an Amazon S3
     * <code>DataSource</code>. The <code>DataSchema</code> defines the structure of
     * the observation data in the data file(s) referenced in the
     * <code>DataSource</code>.</p> <p>Define your <code>DataSchema</code> as a series
     * of key-value pairs. <code>attributes</code> and
     * <code>excludedVariableNames</code> have an array of key-value pairs for their
     * value. Use the following format to define your <code>DataSchema</code>.</p> <p>{
     * "version": "1.0",</p> <p> "recordAnnotationFieldName": "F1",</p> <p>
     * "recordWeightFieldName": "F2",</p> <p> "targetFieldName": "F3",</p> <p>
     * "dataFormat": "CSV",</p> <p> "dataFileContainsHeader": true,</p> <p>
     * "attributes": [</p> <p> { "fieldName": "F1", "fieldType": "TEXT" }, {
     * "fieldName": "F2", "fieldType": "NUMERIC" }, { "fieldName": "F3", "fieldType":
     * "CATEGORICAL" }, { "fieldName": "F4", "fieldType": "NUMERIC" }, { "fieldName":
     * "F5", "fieldType": "CATEGORICAL" }, { "fieldName": "F6", "fieldType": "TEXT" },
     * { "fieldName": "F7", "fieldType": "WEIGHTED_INT_SEQUENCE" }, { "fieldName":
     * "F8", "fieldType": "WEIGHTED_STRING_SEQUENCE" } ],</p> <p>
     * "excludedVariableNames": [ "F6" ] } </p> <?oxy_insert_end>
     */
    inline S3DataSpec& WithDataSchema(const char* value) { SetDataSchema(value); return *this;}

    /**
     * <p>Describes the schema Location in Amazon S3.</p>
     */
    inline const Aws::String& GetDataSchemaLocationS3() const{ return m_dataSchemaLocationS3; }

    /**
     * <p>Describes the schema Location in Amazon S3.</p>
     */
    inline void SetDataSchemaLocationS3(const Aws::String& value) { m_dataSchemaLocationS3HasBeenSet = true; m_dataSchemaLocationS3 = value; }

    /**
     * <p>Describes the schema Location in Amazon S3.</p>
     */
    inline void SetDataSchemaLocationS3(Aws::String&& value) { m_dataSchemaLocationS3HasBeenSet = true; m_dataSchemaLocationS3 = value; }

    /**
     * <p>Describes the schema Location in Amazon S3.</p>
     */
    inline void SetDataSchemaLocationS3(const char* value) { m_dataSchemaLocationS3HasBeenSet = true; m_dataSchemaLocationS3.assign(value); }

    /**
     * <p>Describes the schema Location in Amazon S3.</p>
     */
    inline S3DataSpec& WithDataSchemaLocationS3(const Aws::String& value) { SetDataSchemaLocationS3(value); return *this;}

    /**
     * <p>Describes the schema Location in Amazon S3.</p>
     */
    inline S3DataSpec& WithDataSchemaLocationS3(Aws::String&& value) { SetDataSchemaLocationS3(value); return *this;}

    /**
     * <p>Describes the schema Location in Amazon S3.</p>
     */
    inline S3DataSpec& WithDataSchemaLocationS3(const char* value) { SetDataSchemaLocationS3(value); return *this;}

  private:
    Aws::String m_dataLocationS3;
    bool m_dataLocationS3HasBeenSet;
    Aws::String m_dataRearrangement;
    bool m_dataRearrangementHasBeenSet;
    Aws::String m_dataSchema;
    bool m_dataSchemaHasBeenSet;
    Aws::String m_dataSchemaLocationS3;
    bool m_dataSchemaLocationS3HasBeenSet;
  };

} // namespace Model
} // namespace MachineLearning
} // namespace Aws
