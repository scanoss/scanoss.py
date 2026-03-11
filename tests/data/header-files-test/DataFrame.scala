/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.spark.sql

import scala.collection.mutable.ArrayBuffer
import scala.reflect.runtime.universe.TypeTag

import org.apache.spark.annotation.{DeveloperApi, Evolving}
import org.apache.spark.api.java.function._
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.types.StructType

class DataFrame private[sql](
    @transient val sparkSession: SparkSession,
    @DeveloperApi @Evolving val queryExecution: QueryExecution)
  extends Dataset[Row] {

  def select(cols: Column*): DataFrame = {
    val outputColumns = cols.map(_.named)
    sparkSession.sessionState.executePlan(
      Project(outputColumns, queryExecution.logical))
      .toDataFrame
  }

  def filter(condition: Column): DataFrame = {
    sparkSession.sessionState.executePlan(
      Filter(condition.expr, queryExecution.logical))
      .toDataFrame
  }

  def groupBy(cols: Column*): RelationalGroupedDataset = {
    new RelationalGroupedDataset(
      this,
      cols.map(_.expr),
      RelationalGroupedDataset.GroupByType)
  }

  def join(right: DataFrame, joinExprs: Column): DataFrame = {
    join(right, joinExprs, "inner")
  }

  def join(right: DataFrame, joinExprs: Column, joinType: String): DataFrame = {
    sparkSession.sessionState.executePlan(
      Join(queryExecution.logical, right.queryExecution.logical,
        JoinType(joinType), Some(joinExprs.expr), JoinHint.NONE))
      .toDataFrame
  }

  def count(): Long = {
    groupBy().count().collect().head.getLong(0)
  }

  override def toString: String = {
    s"DataFrame[${schema.map(f => s"${f.name}: ${f.dataType}").mkString(", ")}]"
  }
}