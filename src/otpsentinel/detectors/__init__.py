from .base import Context, Detector
from .budget import SpendBudget
from .history import ResendWithoutVerify, VerificationRatio
from .population import (ClientIntegrity, ConversionMismatch, CountryShare, IpRotation,
                         NetworkConcentration, Pacing, PrefixBurst)
from .request import DestinationRisk, PurposeCap

ALL = [PurposeCap, DestinationRisk, ResendWithoutVerify, VerificationRatio, CountryShare,
       PrefixBurst, Pacing, NetworkConcentration, IpRotation, ClientIntegrity,
       ConversionMismatch, SpendBudget]

# detectors a solved CAPTCHA says something about; destination detectors keep their weight
CLIENT_SIDE = {"D7", "D8", "D9", "D10"}

__all__ = ["Context", "Detector", "ALL", "CLIENT_SIDE"] + [d.__name__ for d in ALL]
