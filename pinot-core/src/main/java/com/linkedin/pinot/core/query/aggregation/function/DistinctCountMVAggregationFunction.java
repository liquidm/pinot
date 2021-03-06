/**
 * Copyright (C) 2014-2018 LinkedIn Corp. (pinot-core@linkedin.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.linkedin.pinot.core.query.aggregation.function;

import com.linkedin.pinot.common.data.FieldSpec;
import com.linkedin.pinot.core.common.BlockValSet;
import com.linkedin.pinot.core.query.aggregation.AggregationResultHolder;
import com.linkedin.pinot.core.query.aggregation.groupby.GroupByResultHolder;
import it.unimi.dsi.fastutil.ints.IntOpenHashSet;
import javax.annotation.Nonnull;


public class DistinctCountMVAggregationFunction extends DistinctCountAggregationFunction {

  @Nonnull
  @Override
  public AggregationFunctionType getType() {
    return AggregationFunctionType.DISTINCTCOUNTMV;
  }

  @Nonnull
  @Override
  public String getColumnName(@Nonnull String column) {
    return AggregationFunctionType.DISTINCTCOUNTMV.getName() + "_" + column;
  }

  @Override
  public void aggregate(int length, @Nonnull AggregationResultHolder aggregationResultHolder,
      @Nonnull BlockValSet... blockValSets) {
    IntOpenHashSet valueSet = getValueSet(aggregationResultHolder);

    FieldSpec.DataType valueType = blockValSets[0].getValueType();
    switch (valueType) {
      case INT:
        int[][] intValues = blockValSets[0].getIntValuesMV();
        for (int i = 0; i < length; i++) {
          for (int value : intValues[i]) {
            valueSet.add(value);
          }
        }
        break;
      case LONG:
        long[][] longValues = blockValSets[0].getLongValuesMV();
        for (int i = 0; i < length; i++) {
          for (long value : longValues[i]) {
            valueSet.add(Long.hashCode(value));
          }
        }
        break;
      case FLOAT:
        float[][] floatValues = blockValSets[0].getFloatValuesMV();
        for (int i = 0; i < length; i++) {
          for (float value : floatValues[i]) {
            valueSet.add(Float.hashCode(value));
          }
        }
      case DOUBLE:
        double[][] doubleValues = blockValSets[0].getDoubleValuesMV();
        for (int i = 0; i < length; i++) {
          for (double value : doubleValues[i]) {
            valueSet.add(Double.hashCode(value));
          }
        }
        break;
      case STRING:
        String[][] stringValues = blockValSets[0].getStringValuesMV();
        for (int i = 0; i < length; i++) {
          for (String value : stringValues[i]) {
            valueSet.add(value.hashCode());
          }
        }
        break;
      default:
        throw new IllegalStateException("Illegal data type for DISTINCT_COUNT_MV aggregation function: " + valueType);
    }
  }

  @Override
  public void aggregateGroupBySV(int length, @Nonnull int[] groupKeyArray,
      @Nonnull GroupByResultHolder groupByResultHolder, @Nonnull BlockValSet... blockValSets) {
    FieldSpec.DataType valueType = blockValSets[0].getValueType();
    switch (valueType) {
      case INT:
        int[][] intValues = blockValSets[0].getIntValuesMV();
        for (int i = 0; i < length; i++) {
          IntOpenHashSet valueSet = getValueSet(groupByResultHolder, groupKeyArray[i]);
          for (int value : intValues[i]) {
            valueSet.add(value);
          }
        }
        break;
      case LONG:
        long[][] longValues = blockValSets[0].getLongValuesMV();
        for (int i = 0; i < length; i++) {
          IntOpenHashSet valueSet = getValueSet(groupByResultHolder, groupKeyArray[i]);
          for (long value : longValues[i]) {
            valueSet.add(Long.hashCode(value));
          }
        }
        break;
      case FLOAT:
        float[][] floatValues = blockValSets[0].getFloatValuesMV();
        for (int i = 0; i < length; i++) {
          IntOpenHashSet valueSet = getValueSet(groupByResultHolder, groupKeyArray[i]);
          for (float value : floatValues[i]) {
            valueSet.add(Float.hashCode(value));
          }
        }
        break;
      case DOUBLE:
        double[][] doubleValues = blockValSets[0].getDoubleValuesMV();
        for (int i = 0; i < length; i++) {
          IntOpenHashSet valueSet = getValueSet(groupByResultHolder, groupKeyArray[i]);
          for (double value : doubleValues[i]) {
            valueSet.add(Double.hashCode(value));
          }
        }
        break;
      case STRING:
        String[][] stringValues = blockValSets[0].getStringValuesMV();
        for (int i = 0; i < length; i++) {
          IntOpenHashSet valueSet = getValueSet(groupByResultHolder, groupKeyArray[i]);
          for (String value : stringValues[i]) {
            valueSet.add(value.hashCode());
          }
        }
        break;
      default:
        throw new IllegalStateException("Illegal data type for DISTINCT_COUNT_MV aggregation function: " + valueType);
    }
  }

  @Override
  public void aggregateGroupByMV(int length, @Nonnull int[][] groupKeysArray,
      @Nonnull GroupByResultHolder groupByResultHolder, @Nonnull BlockValSet... blockValSets) {
    FieldSpec.DataType valueType = blockValSets[0].getValueType();
    switch (valueType) {
      case INT:
        int[][] intValues = blockValSets[0].getIntValuesMV();
        for (int i = 0; i < length; i++) {
          for (int groupKey : groupKeysArray[i]) {
            IntOpenHashSet valueSet = getValueSet(groupByResultHolder, groupKey);
            for (int value : intValues[i]) {
              valueSet.add(value);
            }
          }
        }
        break;
      case LONG:
        long[][] longValues = blockValSets[0].getLongValuesMV();
        for (int i = 0; i < length; i++) {
          for (int groupKey : groupKeysArray[i]) {
            IntOpenHashSet valueSet = getValueSet(groupByResultHolder, groupKey);
            for (long value : longValues[i]) {
              valueSet.add(Long.hashCode(value));
            }
          }
        }
        break;
      case FLOAT:
        float[][] floatValues = blockValSets[0].getFloatValuesMV();
        for (int i = 0; i < length; i++) {
          for (int groupKey : groupKeysArray[i]) {
            IntOpenHashSet valueSet = getValueSet(groupByResultHolder, groupKey);
            for (float value : floatValues[i]) {
              valueSet.add(Float.hashCode(value));
            }
          }
        }
        break;
      case DOUBLE:
        double[][] doubleValues = blockValSets[0].getDoubleValuesMV();
        for (int i = 0; i < length; i++) {
          for (int groupKey : groupKeysArray[i]) {
            IntOpenHashSet valueSet = getValueSet(groupByResultHolder, groupKey);
            for (double value : doubleValues[i]) {
              valueSet.add(Double.hashCode(value));
            }
          }
        }
        break;
      case STRING:
        String[][] stringValues = blockValSets[0].getStringValuesMV();
        for (int i = 0; i < length; i++) {
          for (int groupKey : groupKeysArray[i]) {
            IntOpenHashSet valueSet = getValueSet(groupByResultHolder, groupKey);
            for (String value : stringValues[i]) {
              valueSet.add(value.hashCode());
            }
          }
        }
        break;
      default:
        throw new IllegalStateException("Illegal data type for DISTINCT_COUNT_MV aggregation function: " + valueType);
    }
  }
}
