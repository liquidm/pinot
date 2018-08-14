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
package com.linkedin.pinot.controller.helix.core.util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.apache.helix.AccessOption;
import org.apache.helix.HelixAdmin;
import org.apache.helix.HelixDataAccessor;
import org.apache.helix.HelixDefinedState;
import org.apache.helix.HelixManager;
import org.apache.helix.PropertyKey;
import org.apache.helix.PropertyPathConfig;
import org.apache.helix.PropertyType;
import org.apache.helix.ZNRecord;
import org.apache.helix.controller.HelixControllerMain;
import org.apache.helix.controller.rebalancer.strategy.CrushEdRebalanceStrategy;
import org.apache.helix.manager.zk.ZKHelixAdmin;
import org.apache.helix.manager.zk.ZKHelixDataAccessor;
import org.apache.helix.manager.zk.ZKHelixManager;
import org.apache.helix.manager.zk.ZNRecordSerializer;
import org.apache.helix.manager.zk.ZkBaseDataAccessor;
import org.apache.helix.manager.zk.ZkClient;
import org.apache.helix.messaging.handling.HelixTaskExecutor;
import org.apache.helix.model.HelixConfigScope;
import org.apache.helix.model.HelixConfigScope.ConfigScopeProperty;
import org.apache.helix.model.IdealState;
import org.apache.helix.model.MasterSlaveSMD;
import org.apache.helix.model.Message.MessageType;
import org.apache.helix.model.StateModelDefinition;
import org.apache.helix.model.builder.HelixConfigScopeBuilder;
import org.apache.helix.store.zk.ZkHelixPropertyStore;
import org.apache.helix.tools.StateModelConfigGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.linkedin.pinot.common.utils.CommonConstants;
import com.linkedin.pinot.common.utils.helix.HelixHelper;
import com.linkedin.pinot.controller.helix.core.PinotHelixBrokerResourceOnlineOfflineStateModelGenerator;
import com.linkedin.pinot.controller.helix.core.PinotHelixSegmentOnlineOfflineStateModelGenerator;
import com.linkedin.pinot.controller.helix.core.PinotTableIdealStateBuilder;


/**
 * HelixSetupUtils handles how to create or get a helixCluster in controller.
 *
 *
 */
public class HelixSetupUtils {

  private static final Logger LOGGER = LoggerFactory.getLogger(HelixSetupUtils.class);

  public static synchronized HelixManager setup(String helixClusterName, String zkPath, String pinotControllerInstanceId,
      boolean isUpdateStateModel) {

    try {
      createHelixClusterIfNeeded(helixClusterName, zkPath, isUpdateStateModel);
    } catch (final Exception e) {
      LOGGER.error("Caught exception", e);
      return null;
    }

    try {
      return startHelixControllerInStandadloneMode(helixClusterName, zkPath, pinotControllerInstanceId);
    } catch (final Exception e) {
      LOGGER.error("Caught exception", e);
      return null;
    }
  }

  public static void createHelixClusterIfNeeded(String helixClusterName, String zkPath) {
    createHelixClusterIfNeeded(helixClusterName, zkPath);
  }

  public static void createHelixClusterIfNeeded(String helixClusterName, String zkPath, boolean isUpdateStateModel) {
    final HelixAdmin admin = new ZKHelixAdmin(zkPath);
    final String segmentStateModelName = PinotHelixSegmentOnlineOfflineStateModelGenerator.PINOT_SEGMENT_ONLINE_OFFLINE_STATE_MODEL;

    if (admin.getClusters().contains(helixClusterName)) {
      LOGGER.info("cluster already exists ********************************************* ");
      if (isUpdateStateModel) {
        final StateModelDefinition curStateModelDef = admin.getStateModelDef(helixClusterName, segmentStateModelName);
        List<String> states = curStateModelDef.getStatesPriorityList();
        if (states.contains(PinotHelixSegmentOnlineOfflineStateModelGenerator.CONSUMING_STATE)) {
          LOGGER.info("State model {} already updated to contain CONSUMING state", segmentStateModelName);
          return;
        } else {
          LOGGER.info("Updating {} to add states for low level kafka consumers", segmentStateModelName);
          StateModelDefinition newStateModelDef = PinotHelixSegmentOnlineOfflineStateModelGenerator.generatePinotStateModelDefinition();
          ZkClient zkClient = new ZkClient(zkPath);
          zkClient.waitUntilConnected(20, TimeUnit.SECONDS);
          zkClient.setZkSerializer(new ZNRecordSerializer());
          HelixDataAccessor accessor = new ZKHelixDataAccessor(helixClusterName, new ZkBaseDataAccessor<ZNRecord>(zkClient));
          PropertyKey.Builder keyBuilder = accessor.keyBuilder();
          accessor.setProperty(keyBuilder.stateModelDef(segmentStateModelName), newStateModelDef);
          LOGGER.info("Completed updating statemodel {}", segmentStateModelName);
          zkClient.close();
        }
      }
      return;
    }

    LOGGER.info("Creating a new cluster, as the helix cluster : " + helixClusterName
        + " was not found ********************************************* ");
    admin.addCluster(helixClusterName, false);

    LOGGER.info("Enable auto join.");
    final HelixConfigScope scope =
        new HelixConfigScopeBuilder(ConfigScopeProperty.CLUSTER).forCluster(helixClusterName).build();

    final Map<String, String> props = new HashMap<String, String>();
    props.put(ZKHelixManager.ALLOW_PARTICIPANT_AUTO_JOIN, String.valueOf(true));
    //we need only one segment to be loaded at a time
    props.put(MessageType.STATE_TRANSITION + "." + HelixTaskExecutor.MAX_THREADS, String.valueOf(1));

    admin.setConfig(scope, props);

    LOGGER.info("Adding state model {} (with CONSUMED state) generated using {} **********************************************",
        segmentStateModelName , PinotHelixSegmentOnlineOfflineStateModelGenerator.class.toString());

    // If this is a fresh cluster we are creating, then the cluster will see the CONSUMING state in the
    // state model. But then the servers will never be asked to go to that STATE (whether they have the code
    // to handle it or not) unil we complete the feature using low-level kafka consumers and turn the feature on.
    admin.addStateModelDef(helixClusterName, segmentStateModelName,
        PinotHelixSegmentOnlineOfflineStateModelGenerator.generatePinotStateModelDefinition());

    LOGGER.info("Adding state model definition named : "
        + PinotHelixBrokerResourceOnlineOfflineStateModelGenerator.PINOT_BROKER_RESOURCE_ONLINE_OFFLINE_STATE_MODEL
        + " generated using : " + PinotHelixBrokerResourceOnlineOfflineStateModelGenerator.class.toString()
        + " ********************************************** ");

    admin.addStateModelDef(helixClusterName,
        PinotHelixBrokerResourceOnlineOfflineStateModelGenerator.PINOT_BROKER_RESOURCE_ONLINE_OFFLINE_STATE_MODEL,
        PinotHelixBrokerResourceOnlineOfflineStateModelGenerator.generatePinotStateModelDefinition());


/*    StateModelDefinition stateModel = new StateModelDefinition.Builder("MasterSlave")
        // OFFLINE is the state that the system starts in (initial state is REQUIRED)
        .initialState("OFFLINE")

        // Lowest number here indicates highest priority, no value indicates lowest priority
        .addState("MASTER", 1).addState("SLAVE", 2).addState("OFFLINE")

        // Note the special inclusion of the DROPPED state (REQUIRED)
        .addState(HelixDefinedState.DROPPED.toString())

        // No more than one master allowed
        .upperBound("MASTER", 1)

        // R indicates an upper bound of number of replicas for each partition
        .dynamicUpperBound("SLAVE", "R")

        // Add some high-priority transitions
        .addTransition("SLAVE", "MASTER", 1).addTransition("OFFLINE", "SLAVE", 2)

        // Using the same priority value indicates that these transitions can fire in any order
        .addTransition("MASTER", "SLAVE", 3).addTransition("SLAVE", "OFFLINE", 3)

        // Not specifying a value defaults to lowest priority
        // Notice the inclusion of the OFFLINE to DROPPED transition
        // Since every state has a path to OFFLINE, they each now have a path to DROPPED (REQUIRED)
        .addTransition("OFFLINE", HelixDefinedState.DROPPED.toString())

        // Create the StateModelDefinition instance
        .build();

    admin.addStateModelDef(helixClusterName, "MasterSlave", stateModel);*/


    LOGGER.info("Adding empty ideal state for Broker!");
    HelixHelper.updateResourceConfigsFor(new HashMap<String, String>(), CommonConstants.Helix.BROKER_RESOURCE_INSTANCE,
        helixClusterName, admin);
    IdealState idealState =
        PinotTableIdealStateBuilder.buildEmptyIdealStateForBrokerResource(admin, helixClusterName);
    admin.setResourceIdealState(helixClusterName, CommonConstants.Helix.BROKER_RESOURCE_INSTANCE, idealState);

    LOGGER.info("Adding empty ideal state for lead controller!");
//    IdealState leadControllerIdealState = PinotTableIdealStateBuilder.buildEmptyIdealStateForLeadControllerResource(admin, helixClusterName);
//    admin.setResourceIdealState(helixClusterName, CommonConstants.Helix.LEAD_CONTROLLER_RESOURCE_INSTANCE, leadControllerIdealState);

//    StateModelDefinition stateModelDefinition = MasterSlaveSMD.build();


//    StateModelConfigGenerator generator = new StateModelConfigGenerator();
    admin.addStateModelDef(helixClusterName, "MasterSlave", MasterSlaveSMD.build());

    HelixHelper.updateResourceConfigsFor(new HashMap<String, String>(), CommonConstants.Helix.LEAD_CONTROLLER_RESOURCE_INSTANCE,
        helixClusterName, admin);
    admin.addResource(helixClusterName, CommonConstants.Helix.LEAD_CONTROLLER_RESOURCE_INSTANCE, 20, "MasterSlave",
        IdealState.RebalanceMode.FULL_AUTO.toString());



    IdealState controllerIdealState = admin.getResourceIdealState(helixClusterName, CommonConstants.Helix.LEAD_CONTROLLER_RESOURCE_INSTANCE);
    controllerIdealState.setInstanceGroupTag("controller");
    admin.setResourceIdealState(helixClusterName, CommonConstants.Helix.LEAD_CONTROLLER_RESOURCE_INSTANCE, controllerIdealState);
    admin.rebalance(helixClusterName, CommonConstants.Helix.LEAD_CONTROLLER_RESOURCE_INSTANCE, 2);

    initPropertyStorePath(helixClusterName, zkPath);
    LOGGER.info("New Cluster setup completed... ********************************************** ");
  }

  private static void initPropertyStorePath(String helixClusterName, String zkPath) {
    String propertyStorePath = PropertyPathConfig.getPath(PropertyType.PROPERTYSTORE, helixClusterName);
    ZkHelixPropertyStore<ZNRecord> propertyStore = new ZkHelixPropertyStore<ZNRecord>(zkPath, new ZNRecordSerializer(), propertyStorePath);
    propertyStore.create("/CONFIGS", new ZNRecord(""), AccessOption.PERSISTENT);
    propertyStore.create("/CONFIGS/CLUSTER", new ZNRecord(""), AccessOption.PERSISTENT);
    propertyStore.create("/CONFIGS/TABLE", new ZNRecord(""), AccessOption.PERSISTENT);
    propertyStore.create("/CONFIGS/INSTANCE", new ZNRecord(""), AccessOption.PERSISTENT);
    propertyStore.create("/SCHEMAS", new ZNRecord(""), AccessOption.PERSISTENT);
    propertyStore.create("/SEGMENTS", new ZNRecord(""), AccessOption.PERSISTENT);
  }

  private static HelixManager startHelixControllerInStandadloneMode(String helixClusterName, String zkUrl,
      String pinotControllerInstanceId) {
    LOGGER.info("Starting Helix Standalone Controller ... ");
    return HelixControllerMain.startHelixController(zkUrl, helixClusterName, pinotControllerInstanceId,
        HelixControllerMain.STANDALONE);
  }
}
