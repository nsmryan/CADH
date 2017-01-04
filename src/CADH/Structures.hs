module CADH.Structures (
) where

import Data.Tree
import Data.Map as M
import Data.Word
import Data.Int

import CADH.DataDefs


-- case studies:
--   locata variable length packets with blocks
--   data set ids in IA/HEU packets
--   single bit part of seq count is data set id for some IAM HS
--   telemetry stream with fixed or varying packet types
--   decoding array of fixed size structures



