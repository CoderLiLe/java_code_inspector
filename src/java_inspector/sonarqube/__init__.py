"""SonarQube — 17 个检查器，覆盖 Bugs / Code Smell / Security 规则"""
from java_inspector.sonarqube.base import BaseSonarChecker, sq_severity
from java_inspector.sonarqube.sonarqube_rules import SonarQubeChecker
from java_inspector.sonarqube.sonarqube_rules_ext import SonarQubeCheckerExt
from java_inspector.sonarqube.sonarqube_rules_full import SonarQubeCheckerFull
from java_inspector.sonarqube.sonarqube_rules_fourth import SonarQubeCheckerFourth
from java_inspector.sonarqube.sonarqube_rules_five import SonarQubeCheckerFive
from java_inspector.sonarqube.sonarqube_rules_six import SonarQubeCheckerSix
from java_inspector.sonarqube.sonarqube_rules_seven import SonarQubeCheckerSeven
from java_inspector.sonarqube.sonarqube_rules_eight import SonarQubeCheckerEight
from java_inspector.sonarqube.sonarqube_rules_nine import SonarQubeCheckerNine
from java_inspector.sonarqube.sonarqube_rules_ten import SonarQubeCheckerTen
from java_inspector.sonarqube.sonarqube_rules_eleven import SonarQubeCheckerEleven
from java_inspector.sonarqube.sonarqube_rules_twelve import SonarQubeCheckerTwelve
from java_inspector.sonarqube.sonarqube_rules_thirteen import SonarQubeCheckerThirteen
from java_inspector.sonarqube.sonarqube_rules_fourteen import SonarQubeCheckerFourteen
from java_inspector.sonarqube.sonarqube_rules_fifteen import SonarQubeCheckerFifteen
from java_inspector.sonarqube.sonarqube_rules_sixteen import SonarQubeCheckerSixteen
from java_inspector.sonarqube.sonarqube_rules_seventeen import SonarQubeCheckerSeventeen

_CHECKER_CLASSES = [
    SonarQubeChecker,
    SonarQubeCheckerExt,
    SonarQubeCheckerFull,
    SonarQubeCheckerFourth,
    SonarQubeCheckerFive,
    SonarQubeCheckerSix,
    SonarQubeCheckerSeven,
    SonarQubeCheckerEight,
    SonarQubeCheckerNine,
    SonarQubeCheckerTen,
    SonarQubeCheckerEleven,
    SonarQubeCheckerTwelve,
    SonarQubeCheckerThirteen,
    SonarQubeCheckerFourteen,
    SonarQubeCheckerFifteen,
    SonarQubeCheckerSixteen,
    SonarQubeCheckerSeventeen,
]


def get_checker_classes():
    """返回所有 SonarQube 检查器类的列表"""
    return list(_CHECKER_CLASSES)


__all__ = [
    "BaseSonarChecker",
    "sq_severity",
    "get_checker_classes",
    "SonarQubeChecker",
    "SonarQubeCheckerExt",
    "SonarQubeCheckerFull",
    "SonarQubeCheckerFourth",
    "SonarQubeCheckerFive",
    "SonarQubeCheckerSix",
    "SonarQubeCheckerSeven",
    "SonarQubeCheckerEight",
    "SonarQubeCheckerNine",
    "SonarQubeCheckerTen",
    "SonarQubeCheckerEleven",
    "SonarQubeCheckerTwelve",
    "SonarQubeCheckerThirteen",
    "SonarQubeCheckerFourteen",
    "SonarQubeCheckerFifteen",
    "SonarQubeCheckerSixteen",
    "SonarQubeCheckerSeventeen",
]
