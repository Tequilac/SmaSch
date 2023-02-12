from dataclasses import dataclass
from enum import Enum


@dataclass
class Thresholds:
    medium: float
    high: float


@dataclass
class MetricThresholds:
    free_memory: Thresholds
    free_cpu: Thresholds
    temperature: Thresholds


class Metric(Enum):
    FREE_MEMORY = 'free_memory'
    FREE_CPU = 'free_cpu'
    TEMPERATURE = 'temperature'


class ThresholdValue(Enum):
    HIGH = 'high'
    MEDIUM = 'medium'


@dataclass
class Condition:
    attribute: Metric
    value: ThresholdValue


class Action(Enum):
    DELETE_PODS = 'delete_pods'


@dataclass
class Rule:
    conditions: list[Condition]
    action: Action


@dataclass
class Config:
    check_timeout: float
    thresholds: MetricThresholds
    rules: list[Rule]
