import os
import time

import yaml
from kubernetes import config, client
from prometheus_api_client import PrometheusConnect

from logger import logger
from src.types import Config, MetricThresholds, Thresholds, Condition, Metric, ThresholdValue, Action, Rule


def conf_to_obj(conf) -> Config:
    check_timeout = conf['check_timeout']

    free_memory = conf['thresholds']['free_memory']
    free_cpu = conf['thresholds']['free_cpu']
    temperature = conf['thresholds']['temperature']

    free_memory_thresholds = Thresholds(medium=free_memory['medium'], high=free_memory['high'])
    free_cpu_thresholds = Thresholds(medium=free_cpu['medium'], high=free_cpu['high'])
    temperature_thresholds = Thresholds(medium=temperature['medium'], high=temperature['high'])
    thresholds = MetricThresholds(
        free_memory=free_memory_thresholds,
        free_cpu=free_cpu_thresholds,
        temperature=temperature_thresholds,
    )

    rule_objects = []
    rules = conf['rules']
    for rule in rules:
        conditions_objects = []
        conditions = rule['conditions']
        for condition in conditions:
            attribute = Metric[condition['attribute']]
            value = ThresholdValue[condition['value']]
            conditions_objects.append(Condition(attribute=attribute, value=value))
        action = Action[rule['action']]
        rule_objects.append(Rule(conditions=conditions_objects, action=action))
    return Config(check_timeout=check_timeout, thresholds=thresholds, rules=rule_objects)


class Validator:
    def __init__(self):
        self._config = None
        self._file_stamp = 0
        self._file_path = '/res/config/conf.yaml'
        self._check_timeout = 10
        self._thresholds: MetricThresholds | None = None
        self._rules: list[Rule] = []
        self._labels = {}

        config.load_kube_config()

        self._kube_api = client.CoreV1Api()

    def start_loop(self):
        logger.info('Starting')
        while True:
            changes = self.get_file_changes()
            if changes:
                self._check_timeout = changes.check_timeout
                self._thresholds = changes.thresholds
                self._rules = changes.rules
            self.validate()
            self.evaluate_rules()
            time.sleep(self._check_timeout)

    def get_file_changes(self) -> Config | None:
        modified_time = os.stat(self._file_path).st_mtime
        if modified_time != self._file_stamp:
            logger.warn('Detected changes, reloading configuration')
            self._file_stamp = modified_time
            conf = self.load_from_file()
            try:
                return conf_to_obj(conf)
            except KeyError:
                logger.warn('Invalid configuration, keeping last one')
                return None
        return None

    def load_from_file(self):
        with open(self._file_path, 'r') as stream:
            conf = yaml.safe_load(stream)
        return conf

    def validate(self):
        nodes = self._kube_api.list_node(watch=False).items
        for node in nodes:
            labels = node.metadata.labels
            allocatable = node.status.allocatable
            capacity = node.status.capacity

            free_cpu = int(capacity['cpu']) * 1000 - int(allocatable['cpu'].split('m')[0])
            free_memory = int(capacity['memory'].split('Ki')[0]) - int(allocatable['memory'].split('Ki')[0])

            if free_memory < self._thresholds.free_memory.medium:
                labels['sma-mem'] = 'sma-mem-low'
            elif self._thresholds.free_memory.medium <= free_memory < self._thresholds.free_memory.high:
                labels['sma-mem'] = 'sma-mem-mid'
            elif free_memory >= self._thresholds.free_memory.high:
                labels['sma-mem'] = 'sma-mem-high'

            if free_cpu < self._thresholds.free_cpu.medium:
                labels['sma-cpu'] = 'sma-cpu-low'
            elif self._thresholds.free_cpu.medium <= free_cpu < self._thresholds.free_cpu.high:
                labels['sma-cpu'] = 'sma-cpu-mid'
            elif free_cpu >= self._thresholds.free_cpu.high:
                labels['sma-cpu'] = 'sma-cpu-high'

            prometheus_url = os.getenv('PROM_URL')
            prom = PrometheusConnect(url=prometheus_url, disable_ssl=True)
            label_config = {'instance': node.metadata.name}
            metric = prom.get_current_metric_value(metric_name='node_hwmon_temp_celsius', label_config=label_config)
            temperature = metric[0].value

            if temperature < self._thresholds.temperature.medium:
                labels['sma-temp'] = 'sma-temp-low'
            elif self._thresholds.temperature.medium <= temperature < self._thresholds.temperature.high:
                labels['sma-temp'] = 'sma-temp-mid'
            elif temperature >= self._thresholds.temperature.high:
                labels['sma-temp'] = 'sma-temp-high'

            self._labels[node.metadata.name] = labels

            body = {
                'metadata': {
                    'labels': labels
                }
            }
            self._kube_api.patch_node(name=node.metadata.name, body=body)

    def evaluate_rules(self):
        nodes = self._kube_api.list_node(watch=False).items
        for node in nodes:
            for rule in self._rules:
                results = [self.evaluate_condition(node, cond) for cond in rule.conditions]
                if all(results):
                    self.perform_action(node, rule.action)

    def perform_action(self, node, action: Action):
        if action == Action.DELETE_PODS:
            pods = self._kube_api.list_namespaced_pod(namespace='default').items
            for pod in pods:
                if pod.spec.node_name == node.metadata.name:
                    self._kube_api.delete_namespaced_pod(pod.metadata.name, namespace='default')

    def evaluate_condition(self, node, condition: Condition):
        labels = self._labels[node.metadata.name]
        if condition.attribute == Metric.FREE_MEMORY:
            if condition.value == ThresholdValue.MEDIUM:
                return labels['sma-mem'] == 'sma-mem-low'
            elif condition.value == ThresholdValue.HIGH:
                return labels['sma-mem'] != 'sma-mem-high'
        elif condition.attribute == Metric.FREE_CPU:
            if condition.value == ThresholdValue.MEDIUM:
                return labels['sma-cpu'] == 'sma-cpu-low'
            elif condition.value == ThresholdValue.HIGH:
                return labels['sma-cpu'] != 'sma-cpu-high'
        elif condition.attribute == Metric.TEMPERATURE:
            if condition.value == ThresholdValue.HIGH:
                return labels['sma-temp'] == 'sma-temp-high'
            elif condition.value == ThresholdValue.MEDIUM:
                return labels['sma-temp'] != 'sma-temp-low'
