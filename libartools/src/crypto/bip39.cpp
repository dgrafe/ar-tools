// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2026 Daniel Grafe <dgrafe@dgrafe.de>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <cstring>
#include <iomanip>
#include <sstream>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <crypto/bip39.h>
#include <crypto/sha256.h>

const std::array<std::string, 2048> wordList = {
    "abandon",  "ability",  "able",     "about",    "above",    "absent",
    "absorb",   "abstract", "absurd",   "abuse",    "access",   "accident",
    "account",  "accuse",   "achieve",  "acid",     "acoustic", "acquire",
    "across",   "act",      "action",   "actor",    "actress",  "actual",
    "adapt",    "add",      "addict",   "address",  "adjust",   "admit",
    "adult",    "advance",  "advice",   "aerobic",  "affair",   "afford",
    "afraid",   "again",    "age",      "agent",    "agree",    "ahead",
    "aim",      "air",      "airport",  "aisle",    "alarm",    "album",
    "alcohol",  "alert",    "alien",    "all",      "alley",    "allow",
    "almost",   "alone",    "alpha",    "already",  "also",     "alter",
    "always",   "amateur",  "amazing",  "among",    "amount",   "amused",
    "analyst",  "anchor",   "ancient",  "anger",    "angle",    "angry",
    "animal",   "ankle",    "announce", "annual",   "another",  "answer",
    "antenna",  "antique",  "anxiety",  "any",      "apart",    "apology",
    "appear",   "apple",    "approve",  "april",    "arch",     "arctic",
    "area",     "arena",    "argue",    "arm",      "armed",    "armor",
    "army",     "around",   "arrange",  "arrest",   "arrive",   "arrow",
    "art",      "artefact", "artist",   "artwork",  "ask",      "aspect",
    "assault",  "asset",    "assist",   "assume",   "asthma",   "athlete",
    "atom",     "attack",   "attend",   "attitude", "attract",  "auction",
    "audit",    "august",   "aunt",     "author",   "auto",     "autumn",
    "average",  "avocado",  "avoid",    "awake",    "aware",    "away",
    "awesome",  "awful",    "awkward",  "axis",     "baby",     "bachelor",
    "bacon",    "badge",    "bag",      "balance",  "balcony",  "ball",
    "bamboo",   "banana",   "banner",   "bar",      "barely",   "bargain",
    "barrel",   "base",     "basic",    "basket",   "battle",   "beach",
    "bean",     "beauty",   "because",  "become",   "beef",     "before",
    "begin",    "behave",   "behind",   "believe",  "below",    "belt",
    "bench",    "benefit",  "best",     "betray",   "better",   "between",
    "beyond",   "bicycle",  "bid",      "bike",     "bind",     "biology",
    "bird",     "birth",    "bitter",   "black",    "blade",    "blame",
    "blanket",  "blast",    "bleak",    "bless",    "blind",    "blood",
    "blossom",  "blouse",   "blue",     "blur",     "blush",    "board",
    "boat",     "body",     "boil",     "bomb",     "bone",     "bonus",
    "book",     "boost",    "border",   "boring",   "borrow",   "boss",
    "bottom",   "bounce",   "box",      "boy",      "bracket",  "brain",
    "brand",    "brass",    "brave",    "bread",    "breeze",   "brick",
    "bridge",   "brief",    "bright",   "bring",    "brisk",    "broccoli",
    "broken",   "bronze",   "broom",    "brother",  "brown",    "brush",
    "bubble",   "buddy",    "budget",   "buffalo",  "build",    "bulb",
    "bulk",     "bullet",   "bundle",   "bunker",   "burden",   "burger",
    "burst",    "bus",      "business", "busy",     "butter",   "buyer",
    "buzz",     "cabbage",  "cabin",    "cable",    "cactus",   "cage",
    "cake",     "call",     "calm",     "camera",   "camp",     "can",
    "canal",    "cancel",   "candy",    "cannon",   "canoe",    "canvas",
    "canyon",   "capable",  "capital",  "captain",  "car",      "carbon",
    "card",     "cargo",    "carpet",   "carry",    "cart",     "case",
    "cash",     "casino",   "castle",   "casual",   "cat",      "catalog",
    "catch",    "category", "cattle",   "caught",   "cause",    "caution",
    "cave",     "ceiling",  "celery",   "cement",   "census",   "century",
    "cereal",   "certain",  "chair",    "chalk",    "champion", "change",
    "chaos",    "chapter",  "charge",   "chase",    "chat",     "cheap",
    "check",    "cheese",   "chef",     "cherry",   "chest",    "chicken",
    "chief",    "child",    "chimney",  "choice",   "choose",   "chronic",
    "chuckle",  "chunk",    "churn",    "cigar",    "cinnamon", "circle",
    "citizen",  "city",     "civil",    "claim",    "clap",     "clarify",
    "claw",     "clay",     "clean",    "clerk",    "clever",   "click",
    "client",   "cliff",    "climb",    "clinic",   "clip",     "clock",
    "clog",     "close",    "cloth",    "cloud",    "clown",    "club",
    "clump",    "cluster",  "clutch",   "coach",    "coast",    "coconut",
    "code",     "coffee",   "coil",     "coin",     "collect",  "color",
    "column",   "combine",  "come",     "comfort",  "comic",    "common",
    "company",  "concert",  "conduct",  "confirm",  "congress", "connect",
    "consider", "control",  "convince", "cook",     "cool",     "copper",
    "copy",     "coral",    "core",     "corn",     "correct",  "cost",
    "cotton",   "couch",    "country",  "couple",   "course",   "cousin",
    "cover",    "coyote",   "crack",    "cradle",   "craft",    "cram",
    "crane",    "crash",    "crater",   "crawl",    "crazy",    "cream",
    "credit",   "creek",    "crew",     "cricket",  "crime",    "crisp",
    "critic",   "crop",     "cross",    "crouch",   "crowd",    "crucial",
    "cruel",    "cruise",   "crumble",  "crunch",   "crush",    "cry",
    "crystal",  "cube",     "culture",  "cup",      "cupboard", "curious",
    "current",  "curtain",  "curve",    "cushion",  "custom",   "cute",
    "cycle",    "dad",      "damage",   "damp",     "dance",    "danger",
    "daring",   "dash",     "daughter", "dawn",     "day",      "deal",
    "debate",   "debris",   "decade",   "december", "decide",   "decline",
    "decorate", "decrease", "deer",     "defense",  "define",   "defy",
    "degree",   "delay",    "deliver",  "demand",   "demise",   "denial",
    "dentist",  "deny",     "depart",   "depend",   "deposit",  "depth",
    "deputy",   "derive",   "describe", "desert",   "design",   "desk",
    "despair",  "destroy",  "detail",   "detect",   "develop",  "device",
    "devote",   "diagram",  "dial",     "diamond",  "diary",    "dice",
    "diesel",   "diet",     "differ",   "digital",  "dignity",  "dilemma",
    "dinner",   "dinosaur", "direct",   "dirt",     "disagree", "discover",
    "disease",  "dish",     "dismiss",  "disorder", "display",  "distance",
    "divert",   "divide",   "divorce",  "dizzy",    "doctor",   "document",
    "dog",      "doll",     "dolphin",  "domain",   "donate",   "donkey",
    "donor",    "door",     "dose",     "double",   "dove",     "draft",
    "dragon",   "drama",    "drastic",  "draw",     "dream",    "dress",
    "drift",    "drill",    "drink",    "drip",     "drive",    "drop",
    "drum",     "dry",      "duck",     "dumb",     "dune",     "during",
    "dust",     "dutch",    "duty",     "dwarf",    "dynamic",  "eager",
    "eagle",    "early",    "earn",     "earth",    "easily",   "east",
    "easy",     "echo",     "ecology",  "economy",  "edge",     "edit",
    "educate",  "effort",   "egg",      "eight",    "either",   "elbow",
    "elder",    "electric", "elegant",  "element",  "elephant", "elevator",
    "elite",    "else",     "embark",   "embody",   "embrace",  "emerge",
    "emotion",  "employ",   "empower",  "empty",    "enable",   "enact",
    "end",      "endless",  "endorse",  "enemy",    "energy",   "enforce",
    "engage",   "engine",   "enhance",  "enjoy",    "enlist",   "enough",
    "enrich",   "enroll",   "ensure",   "enter",    "entire",   "entry",
    "envelope", "episode",  "equal",    "equip",    "era",      "erase",
    "erode",    "erosion",  "error",    "erupt",    "escape",   "essay",
    "essence",  "estate",   "eternal",  "ethics",   "evidence", "evil",
    "evoke",    "evolve",   "exact",    "example",  "excess",   "exchange",
    "excite",   "exclude",  "excuse",   "execute",  "exercise", "exhaust",
    "exhibit",  "exile",    "exist",    "exit",     "exotic",   "expand",
    "expect",   "expire",   "explain",  "expose",   "express",  "extend",
    "extra",    "eye",      "eyebrow",  "fabric",   "face",     "faculty",
    "fade",     "faint",    "faith",    "fall",     "false",    "fame",
    "family",   "famous",   "fan",      "fancy",    "fantasy",  "farm",
    "fashion",  "fat",      "fatal",    "father",   "fatigue",  "fault",
    "favorite", "feature",  "february", "federal",  "fee",      "feed",
    "feel",     "female",   "fence",    "festival", "fetch",    "fever",
    "few",      "fiber",    "fiction",  "field",    "figure",   "file",
    "film",     "filter",   "final",    "find",     "fine",     "finger",
    "finish",   "fire",     "firm",     "first",    "fiscal",   "fish",
    "fit",      "fitness",  "fix",      "flag",     "flame",    "flash",
    "flat",     "flavor",   "flee",     "flight",   "flip",     "float",
    "flock",    "floor",    "flower",   "fluid",    "flush",    "fly",
    "foam",     "focus",    "fog",      "foil",     "fold",     "follow",
    "food",     "foot",     "force",    "forest",   "forget",   "fork",
    "fortune",  "forum",    "forward",  "fossil",   "foster",   "found",
    "fox",      "fragile",  "frame",    "frequent", "fresh",    "friend",
    "fringe",   "frog",     "front",    "frost",    "frown",    "frozen",
    "fruit",    "fuel",     "fun",      "funny",    "furnace",  "fury",
    "future",   "gadget",   "gain",     "galaxy",   "gallery",  "game",
    "gap",      "garage",   "garbage",  "garden",   "garlic",   "garment",
    "gas",      "gasp",     "gate",     "gather",   "gauge",    "gaze",
    "general",  "genius",   "genre",    "gentle",   "genuine",  "gesture",
    "ghost",    "giant",    "gift",     "giggle",   "ginger",   "giraffe",
    "girl",     "give",     "glad",     "glance",   "glare",    "glass",
    "glide",    "glimpse",  "globe",    "gloom",    "glory",    "glove",
    "glow",     "glue",     "goat",     "goddess",  "gold",     "good",
    "goose",    "gorilla",  "gospel",   "gossip",   "govern",   "gown",
    "grab",     "grace",    "grain",    "grant",    "grape",    "grass",
    "gravity",  "great",    "green",    "grid",     "grief",    "grit",
    "grocery",  "group",    "grow",     "grunt",    "guard",    "guess",
    "guide",    "guilt",    "guitar",   "gun",      "gym",      "habit",
    "hair",     "half",     "hammer",   "hamster",  "hand",     "happy",
    "harbor",   "hard",     "harsh",    "harvest",  "hat",      "have",
    "hawk",     "hazard",   "head",     "health",   "heart",    "heavy",
    "hedgehog", "height",   "hello",    "helmet",   "help",     "hen",
    "hero",     "hidden",   "high",     "hill",     "hint",     "hip",
    "hire",     "history",  "hobby",    "hockey",   "hold",     "hole",
    "holiday",  "hollow",   "home",     "honey",    "hood",     "hope",
    "horn",     "horror",   "horse",    "hospital", "host",     "hotel",
    "hour",     "hover",    "hub",      "huge",     "human",    "humble",
    "humor",    "hundred",  "hungry",   "hunt",     "hurdle",   "hurry",
    "hurt",     "husband",  "hybrid",   "ice",      "icon",     "idea",
    "identify", "idle",     "ignore",   "ill",      "illegal",  "illness",
    "image",    "imitate",  "immense",  "immune",   "impact",   "impose",
    "improve",  "impulse",  "inch",     "include",  "income",   "increase",
    "index",    "indicate", "indoor",   "industry", "infant",   "inflict",
    "inform",   "inhale",   "inherit",  "initial",  "inject",   "injury",
    "inmate",   "inner",    "innocent", "input",    "inquiry",  "insane",
    "insect",   "inside",   "inspire",  "install",  "intact",   "interest",
    "into",     "invest",   "invite",   "involve",  "iron",     "island",
    "isolate",  "issue",    "item",     "ivory",    "jacket",   "jaguar",
    "jar",      "jazz",     "jealous",  "jeans",    "jelly",    "jewel",
    "job",      "join",     "joke",     "journey",  "joy",      "judge",
    "juice",    "jump",     "jungle",   "junior",   "junk",     "just",
    "kangaroo", "keen",     "keep",     "ketchup",  "key",      "kick",
    "kid",      "kidney",   "kind",     "kingdom",  "kiss",     "kit",
    "kitchen",  "kite",     "kitten",   "kiwi",     "knee",     "knife",
    "knock",    "know",     "lab",      "label",    "labor",    "ladder",
    "lady",     "lake",     "lamp",     "language", "laptop",   "large",
    "later",    "latin",    "laugh",    "laundry",  "lava",     "law",
    "lawn",     "lawsuit",  "layer",    "lazy",     "leader",   "leaf",
    "learn",    "leave",    "lecture",  "left",     "leg",      "legal",
    "legend",   "leisure",  "lemon",    "lend",     "length",   "lens",
    "leopard",  "lesson",   "letter",   "level",    "liar",     "liberty",
    "library",  "license",  "life",     "lift",     "light",    "like",
    "limb",     "limit",    "link",     "lion",     "liquid",   "list",
    "little",   "live",     "lizard",   "load",     "loan",     "lobster",
    "local",    "lock",     "logic",    "lonely",   "long",     "loop",
    "lottery",  "loud",     "lounge",   "love",     "loyal",    "lucky",
    "luggage",  "lumber",   "lunar",    "lunch",    "luxury",   "lyrics",
    "machine",  "mad",      "magic",    "magnet",   "maid",     "mail",
    "main",     "major",    "make",     "mammal",   "man",      "manage",
    "mandate",  "mango",    "mansion",  "manual",   "maple",    "marble",
    "march",    "margin",   "marine",   "market",   "marriage", "mask",
    "mass",     "master",   "match",    "material", "math",     "matrix",
    "matter",   "maximum",  "maze",     "meadow",   "mean",     "measure",
    "meat",     "mechanic", "medal",    "media",    "melody",   "melt",
    "member",   "memory",   "mention",  "menu",     "mercy",    "merge",
    "merit",    "merry",    "mesh",     "message",  "metal",    "method",
    "middle",   "midnight", "milk",     "million",  "mimic",    "mind",
    "minimum",  "minor",    "minute",   "miracle",  "mirror",   "misery",
    "miss",     "mistake",  "mix",      "mixed",    "mixture",  "mobile",
    "model",    "modify",   "mom",      "moment",   "monitor",  "monkey",
    "monster",  "month",    "moon",     "moral",    "more",     "morning",
    "mosquito", "mother",   "motion",   "motor",    "mountain", "mouse",
    "move",     "movie",    "much",     "muffin",   "mule",     "multiply",
    "muscle",   "museum",   "mushroom", "music",    "must",     "mutual",
    "myself",   "mystery",  "myth",     "naive",    "name",     "napkin",
    "narrow",   "nasty",    "nation",   "nature",   "near",     "neck",
    "need",     "negative", "neglect",  "neither",  "nephew",   "nerve",
    "nest",     "net",      "network",  "neutral",  "never",    "news",
    "next",     "nice",     "night",    "noble",    "noise",    "nominee",
    "noodle",   "normal",   "north",    "nose",     "notable",  "note",
    "nothing",  "notice",   "novel",    "now",      "nuclear",  "number",
    "nurse",    "nut",      "oak",      "obey",     "object",   "oblige",
    "obscure",  "observe",  "obtain",   "obvious",  "occur",    "ocean",
    "october",  "odor",     "off",      "offer",    "office",   "often",
    "oil",      "okay",     "old",      "olive",    "olympic",  "omit",
    "once",     "one",      "onion",    "online",   "only",     "open",
    "opera",    "opinion",  "oppose",   "option",   "orange",   "orbit",
    "orchard",  "order",    "ordinary", "organ",    "orient",   "original",
    "orphan",   "ostrich",  "other",    "outdoor",  "outer",    "output",
    "outside",  "oval",     "oven",     "over",     "own",      "owner",
    "oxygen",   "oyster",   "ozone",    "pact",     "paddle",   "page",
    "pair",     "palace",   "palm",     "panda",    "panel",    "panic",
    "panther",  "paper",    "parade",   "parent",   "park",     "parrot",
    "party",    "pass",     "patch",    "path",     "patient",  "patrol",
    "pattern",  "pause",    "pave",     "payment",  "peace",    "peanut",
    "pear",     "peasant",  "pelican",  "pen",      "penalty",  "pencil",
    "people",   "pepper",   "perfect",  "permit",   "person",   "pet",
    "phone",    "photo",    "phrase",   "physical", "piano",    "picnic",
    "picture",  "piece",    "pig",      "pigeon",   "pill",     "pilot",
    "pink",     "pioneer",  "pipe",     "pistol",   "pitch",    "pizza",
    "place",    "planet",   "plastic",  "plate",    "play",     "please",
    "pledge",   "pluck",    "plug",     "plunge",   "poem",     "poet",
    "point",    "polar",    "pole",     "police",   "pond",     "pony",
    "pool",     "popular",  "portion",  "position", "possible", "post",
    "potato",   "pottery",  "poverty",  "powder",   "power",    "practice",
    "praise",   "predict",  "prefer",   "prepare",  "present",  "pretty",
    "prevent",  "price",    "pride",    "primary",  "print",    "priority",
    "prison",   "private",  "prize",    "problem",  "process",  "produce",
    "profit",   "program",  "project",  "promote",  "proof",    "property",
    "prosper",  "protect",  "proud",    "provide",  "public",   "pudding",
    "pull",     "pulp",     "pulse",    "pumpkin",  "punch",    "pupil",
    "puppy",    "purchase", "purity",   "purpose",  "purse",    "push",
    "put",      "puzzle",   "pyramid",  "quality",  "quantum",  "quarter",
    "question", "quick",    "quit",     "quiz",     "quote",    "rabbit",
    "raccoon",  "race",     "rack",     "radar",    "radio",    "rail",
    "rain",     "raise",    "rally",    "ramp",     "ranch",    "random",
    "range",    "rapid",    "rare",     "rate",     "rather",   "raven",
    "raw",      "razor",    "ready",    "real",     "reason",   "rebel",
    "rebuild",  "recall",   "receive",  "recipe",   "record",   "recycle",
    "reduce",   "reflect",  "reform",   "refuse",   "region",   "regret",
    "regular",  "reject",   "relax",    "release",  "relief",   "rely",
    "remain",   "remember", "remind",   "remove",   "render",   "renew",
    "rent",     "reopen",   "repair",   "repeat",   "replace",  "report",
    "require",  "rescue",   "resemble", "resist",   "resource", "response",
    "result",   "retire",   "retreat",  "return",   "reunion",  "reveal",
    "review",   "reward",   "rhythm",   "rib",      "ribbon",   "rice",
    "rich",     "ride",     "ridge",    "rifle",    "right",    "rigid",
    "ring",     "riot",     "ripple",   "risk",     "ritual",   "rival",
    "river",    "road",     "roast",    "robot",    "robust",   "rocket",
    "romance",  "roof",     "rookie",   "room",     "rose",     "rotate",
    "rough",    "round",    "route",    "royal",    "rubber",   "rude",
    "rug",      "rule",     "run",      "runway",   "rural",    "sad",
    "saddle",   "sadness",  "safe",     "sail",     "salad",    "salmon",
    "salon",    "salt",     "salute",   "same",     "sample",   "sand",
    "satisfy",  "satoshi",  "sauce",    "sausage",  "save",     "say",
    "scale",    "scan",     "scare",    "scatter",  "scene",    "scheme",
    "school",   "science",  "scissors", "scorpion", "scout",    "scrap",
    "screen",   "script",   "scrub",    "sea",      "search",   "season",
    "seat",     "second",   "secret",   "section",  "security", "seed",
    "seek",     "segment",  "select",   "sell",     "seminar",  "senior",
    "sense",    "sentence", "series",   "service",  "session",  "settle",
    "setup",    "seven",    "shadow",   "shaft",    "shallow",  "share",
    "shed",     "shell",    "sheriff",  "shield",   "shift",    "shine",
    "ship",     "shiver",   "shock",    "shoe",     "shoot",    "shop",
    "short",    "shoulder", "shove",    "shrimp",   "shrug",    "shuffle",
    "shy",      "sibling",  "sick",     "side",     "siege",    "sight",
    "sign",     "silent",   "silk",     "silly",    "silver",   "similar",
    "simple",   "since",    "sing",     "siren",    "sister",   "situate",
    "six",      "size",     "skate",    "sketch",   "ski",      "skill",
    "skin",     "skirt",    "skull",    "slab",     "slam",     "sleep",
    "slender",  "slice",    "slide",    "slight",   "slim",     "slogan",
    "slot",     "slow",     "slush",    "small",    "smart",    "smile",
    "smoke",    "smooth",   "snack",    "snake",    "snap",     "sniff",
    "snow",     "soap",     "soccer",   "social",   "sock",     "soda",
    "soft",     "solar",    "soldier",  "solid",    "solution", "solve",
    "someone",  "song",     "soon",     "sorry",    "sort",     "soul",
    "sound",    "soup",     "source",   "south",    "space",    "spare",
    "spatial",  "spawn",    "speak",    "special",  "speed",    "spell",
    "spend",    "sphere",   "spice",    "spider",   "spike",    "spin",
    "spirit",   "split",    "spoil",    "sponsor",  "spoon",    "sport",
    "spot",     "spray",    "spread",   "spring",   "spy",      "square",
    "squeeze",  "squirrel", "stable",   "stadium",  "staff",    "stage",
    "stairs",   "stamp",    "stand",    "start",    "state",    "stay",
    "steak",    "steel",    "stem",     "step",     "stereo",   "stick",
    "still",    "sting",    "stock",    "stomach",  "stone",    "stool",
    "story",    "stove",    "strategy", "street",   "strike",   "strong",
    "struggle", "student",  "stuff",    "stumble",  "style",    "subject",
    "submit",   "subway",   "success",  "such",     "sudden",   "suffer",
    "sugar",    "suggest",  "suit",     "summer",   "sun",      "sunny",
    "sunset",   "super",    "supply",   "supreme",  "sure",     "surface",
    "surge",    "surprise", "surround", "survey",   "suspect",  "sustain",
    "swallow",  "swamp",    "swap",     "swarm",    "swear",    "sweet",
    "swift",    "swim",     "swing",    "switch",   "sword",    "symbol",
    "symptom",  "syrup",    "system",   "table",    "tackle",   "tag",
    "tail",     "talent",   "talk",     "tank",     "tape",     "target",
    "task",     "taste",    "tattoo",   "taxi",     "teach",    "team",
    "tell",     "ten",      "tenant",   "tennis",   "tent",     "term",
    "test",     "text",     "thank",    "that",     "theme",    "then",
    "theory",   "there",    "they",     "thing",    "this",     "thought",
    "three",    "thrive",   "throw",    "thumb",    "thunder",  "ticket",
    "tide",     "tiger",    "tilt",     "timber",   "time",     "tiny",
    "tip",      "tired",    "tissue",   "title",    "toast",    "tobacco",
    "today",    "toddler",  "toe",      "together", "toilet",   "token",
    "tomato",   "tomorrow", "tone",     "tongue",   "tonight",  "tool",
    "tooth",    "top",      "topic",    "topple",   "torch",    "tornado",
    "tortoise", "toss",     "total",    "tourist",  "toward",   "tower",
    "town",     "toy",      "track",    "trade",    "traffic",  "tragic",
    "train",    "transfer", "trap",     "trash",    "travel",   "tray",
    "treat",    "tree",     "trend",    "trial",    "tribe",    "trick",
    "trigger",  "trim",     "trip",     "trophy",   "trouble",  "truck",
    "true",     "truly",    "trumpet",  "trust",    "truth",    "try",
    "tube",     "tuition",  "tumble",   "tuna",     "tunnel",   "turkey",
    "turn",     "turtle",   "twelve",   "twenty",   "twice",    "twin",
    "twist",    "two",      "type",     "typical",  "ugly",     "umbrella",
    "unable",   "unaware",  "uncle",    "uncover",  "under",    "undo",
    "unfair",   "unfold",   "unhappy",  "uniform",  "unique",   "unit",
    "universe", "unknown",  "unlock",   "until",    "unusual",  "unveil",
    "update",   "upgrade",  "uphold",   "upon",     "upper",    "upset",
    "urban",    "urge",     "usage",    "use",      "used",     "useful",
    "useless",  "usual",    "utility",  "vacant",   "vacuum",   "vague",
    "valid",    "valley",   "valve",    "van",      "vanish",   "vapor",
    "various",  "vast",     "vault",    "vehicle",  "velvet",   "vendor",
    "venture",  "venue",    "verb",     "verify",   "version",  "very",
    "vessel",   "veteran",  "viable",   "vibrant",  "vicious",  "victory",
    "video",    "view",     "village",  "vintage",  "violin",   "virtual",
    "virus",    "visa",     "visit",    "visual",   "vital",    "vivid",
    "vocal",    "voice",    "void",     "volcano",  "volume",   "vote",
    "voyage",   "wage",     "wagon",    "wait",     "walk",     "wall",
    "walnut",   "want",     "warfare",  "warm",     "warrior",  "wash",
    "wasp",     "waste",    "water",    "wave",     "way",      "wealth",
    "weapon",   "wear",     "weasel",   "weather",  "web",      "wedding",
    "weekend",  "weird",    "welcome",  "west",     "wet",      "whale",
    "what",     "wheat",    "wheel",    "when",     "where",    "whip",
    "whisper",  "wide",     "width",    "wife",     "wild",     "will",
    "win",      "window",   "wine",     "wing",     "wink",     "winner",
    "winter",   "wire",     "wisdom",   "wise",     "wish",     "witness",
    "wolf",     "woman",    "wonder",   "wood",     "wool",     "word",
    "work",     "world",    "worry",    "worth",    "wrap",     "wreck",
    "wrestle",  "wrist",    "write",    "wrong",    "yard",     "year",
    "yellow",   "you",      "young",    "youth",    "zebra",    "zero",
    "zone",     "zoo",
};

namespace artools {
namespace crypto {

/**
 * @brief Constructs a BIP-39 instance with a freshly generated mnemonic.
 *
 * Generates a new 12-word mnemonic from 128 bits of cryptographically secure
 * entropy (see createMnemonicSeed()) and immediately derives the corresponding
 * BIP-39 root seed with an empty passphrase. The resulting mnemonic and seed
 * are retrievable via getMnemonicString() and getRootSeed()/getRootSeedAsHex().
 *
 * @note The generated mnemonic is non-deterministic: it draws from the
 *       operating-system CSPRNG via RAND_bytes(). Deterministic recovery of a
 *       previously generated mnemonic is performed through
 *       initFromMnemonicString().
 */
BIP39::BIP39() {

  createMnemonicSeed();
  _rootSeed = createRootSeed(_mnemonicString, "");
}

/**
 * @brief Overwrites all sensitive state before destruction.
 *
 * The mnemonic sentence, the root seed and the HMAC-DRBG key material are
 * wiped with OPENSSL_cleanse() so they do not linger in freed heap memory.
 * A plain memset() could be elided by the optimiser; OPENSSL_cleanse() is
 * guaranteed to perform the writes.
 */
BIP39::~BIP39() {

  OPENSSL_cleanse(_mnemonicString.data(), _mnemonicString.size());
  OPENSSL_cleanse(_mnemonicSeed.data(), _mnemonicSeed.size() * sizeof(std::uint16_t));
  OPENSSL_cleanse(_rootSeed.data(), _rootSeed.size());
  OPENSSL_cleanse(_drbg.K.data(), _drbg.K.size());
  OPENSSL_cleanse(_drbg.V.data(), _drbg.V.size());
}

/**
 * @brief Generates a new 12-word BIP-39 mnemonic from 128 bits of entropy.
 *
 * Implements the BIP-39 mnemonic encoding algorithm:
 *
 *   1. Draw 128 bits (16 bytes) of entropy from the CSPRNG.
 *   2. Compute SHA-256 over the entropy and take its first byte as the
 *      checksum. The checksum contributes the low 4 bits of the final
 *      (132-bit) bit stream, so the total entropy || checksum length is
 *      128 + 4 = 132 bits.
 *   3. Split the 132-bit stream into twelve 11-bit indices.
 *   4. Map each index into the 2048-word BIP-39 English wordlist and join the
 *      words with single spaces.
 *
 * The 11-bit indices are stored in a 16-bit native word type (MnemonicSeedType)
 * because 11 bits do not align to a byte boundary; the bit extraction walks the
 * entropy stream MSB-first, shifting each extracted bit into the accumulator.
 *
 * @note The checksum is mandatory for BIP-39 validity: it lets a wallet detect
 *       a mistyped word with high probability. The first hash byte supplies the
 *       four checksum bits because the checksum length is entropy/32 = 4 bits.
 *
 * @post _mnemonicString holds the space-separated 12-word sentence and
 *       _mnemonicSeed holds the twelve 11-bit word indices.
 */
void BIP39::createMnemonicSeed() {

  std::string ret;

  // arweave uses 12 word seeds, which equals an entropy of 128 Bits
  const auto entropyBits = 128;
  const auto entropyBytes = entropyBits / 8;

  // padded to 11 bit times 12 words = 132 bits
  const auto totalBytes = entropyBytes + 1;
  std::array<std::uint8_t, totalBytes> randomPattern{};

  // create some entropy for the 128 bits. RAND_bytes() draws from the
  // operating-system CSPRNG and can only fail in a broken entropy state;
  // proceeding with uninitialised memory would silently derive the wallet
  // from garbage, so the failure must be fatal.
  if (RAND_bytes(randomPattern.data(), entropyBytes) != 1)
    throw std::runtime_error(
        std::string("BIP39: CSPRNG failure (RAND_bytes): ") +
        ERR_error_string(ERR_get_error(), nullptr));

  // hash the entropy vector and pad the ramaining 4 bits with the first bits
  // from the hash
  SHA256 randomPatternHash(randomPattern.data(), entropyBytes);
  randomPattern[entropyBytes] = randomPatternHash.getHash()[0];

  // create sequence of 11 bit indizes (stored as 16 bits as this is the native
  // data type)
  MnemonicSeedType wordIndizes{0};

  // walk the entropy stream and bit-shift into the word indizes
  std::uint8_t bitPosition = 7;
  std::uint8_t bytePosition = 0;
  for (auto &wordIndex : wordIndizes) {
    for (auto extractedBits = 0; extractedBits < BIP39::BitsPerWord;
         extractedBits++) {
      wordIndex |= (((randomPattern[bytePosition]) >> bitPosition) & 0x1);

      if (0 == bitPosition) {
        bitPosition = 7;
        bytePosition++;
      } else {
        bitPosition--;
      }

      // shift left in preparation for masking the next bit
      // unless the final 11th bit has already been written
      if (extractedBits < (BIP39::BitsPerWord - 1))
        wordIndex <<= 1;
    }
    ret += wordList[wordIndex] + " ";
  }
  ret.pop_back();

  _mnemonicString = ret;
  _mnemonicSeed = wordIndizes;
}

/**
 * @brief Verifies the BIP-39 checksum embedded in a sequence of word indices.
 *
 * Reconstructs the 132-bit entropy || checksum stream from the twelve 11-bit
 * indices, re-computes SHA-256 over the leading 128 bits and compares the
 * high nibble of the first hash byte against the trailing 4 checksum bits.
 *
 * @param indices the twelve 11-bit wordlist indices
 * @return        true if the checksum matches
 */
static bool verifyChecksum(const BIP39::MnemonicSeedType &indices) {

  // Reassemble the 132-bit stream MSB-first.
  std::array<std::uint8_t, 17> stream{};
  std::uint8_t bitPosition = 7;
  std::uint8_t bytePosition = 0;
  for (const auto index : indices) {
    for (auto extractedBits = 0; extractedBits < BIP39::BitsPerWord;
         extractedBits++) {
      const std::uint8_t bit = (index >> (BIP39::BitsPerWord - 1 -
                                          extractedBits)) &
                               0x1;
      stream[bytePosition] |= bit << bitPosition;

      if (0 == bitPosition) {
        bitPosition = 7;
        bytePosition++;
      } else {
        bitPosition--;
      }
    }
  }

  // The first 16 bytes are the entropy; bits 128..131 of the MSB-first
  // stream occupy the HIGH nibble of byte 16 and carry the checksum.
  // BIP-39 mandates checksum = first SHA-256(entropy) bits.
  SHA256 entropyHash(stream.data(), 16);
  const std::uint8_t expected = entropyHash.getHash()[0] >> 4;
  const std::uint8_t actual = stream[16] >> 4;

  return expected == actual;
}

/**
 * @brief Restores a BIP-39 instance from an existing mnemonic sentence.
 *
 * Parses the space-separated mnemonic, resolves each word to its 11-bit index
 * via a binary search over the alphabetically sorted wordlist, verifies the
 * embedded BIP-39 checksum and derives the BIP-39 root seed with the supplied
 * (possibly empty) passphrase. On success the instance's mnemonic, word
 * indices and root seed are all replaced.
 *
 * @param mnemonicString the 12-word BIP-39 sentence, words separated by single
 *                       spaces
 * @param password       optional BIP-39 passphrase; the empty string (default)
 *                       selects the standard "mnemonic" salt
 * @return               true on success; false if the sentence does not
 *                       contain exactly NumberOfWords words, any word is not
 *                       present in the wordlist or the checksum is invalid
 *
 * @note The passphrase is a BIP-39 extension that adds a second factor to the
 *       seed derivation: two different passphrases over the same mnemonic
 *       yield two different root seeds (and therefore two different wallets).
 *       It is not stored anywhere and must be remembered by the user.
 *
 * @note The checksum verification is a security feature, not a formality: a
 *       mistyped but wordlist-valid mnemonic would otherwise silently derive
 *       a *different* (empty) wallet instead of being rejected.
 */
bool BIP39::initFromMnemonicString(const std::string &mnemonicString,
                                   const std::string &password) {

  std::uint8_t seedIndex = 0;
  std::string delim = " ";
  MnemonicSeedType buf{};

  std::string tokenizer_input = mnemonicString;
  char *token = std::strtok(tokenizer_input.data(), delim.data());
  while (token != nullptr) {

    if (seedIndex >= buf.max_size())
      return false;

    const auto index = indexFromWord(token);
    if (index == BIP39::UNKNOWN_WORD)
      return false;

    buf[seedIndex++] = index;

    token = std::strtok(nullptr, delim.data());
  }

  if (seedIndex != BIP39::NumberOfWords)
    return false;

  // Reject mnemonics whose checksum does not match their entropy: a typo
  // must never silently produce a different wallet.
  if (!verifyChecksum(buf))
    return false;

  _mnemonicSeed = buf;
  _mnemonicString = mnemonicString;
  _rootSeed = createRootSeed(_mnemonicString, password);

  return true;
}

/**
 * @brief Resolves a single mnemonic word to its 11-bit wordlist index.
 *
 * Performs a binary search over the alphabetically sorted 2048-word BIP-39
 * English wordlist. The wordlist is sorted lexicographically, so a standard
 * divide-and-conquer search runs in O(log 2048) = 11 comparisons worst case.
 *
 * @param word the word to look up
 * @return     the 0-based index of @p word in the wordlist, or UNKNOWN_WORD
 *             (0xFFFF) if @p word is not present
 */
std::uint16_t BIP39::indexFromWord(const std::string &word) {

  std::uint16_t low = 0;
  std::uint16_t high = wordList.size() - 1;

  while (low <= high) {

    const std::uint16_t mid = low + (high - low) / 2;
    const auto result = wordList[mid].compare(word);

    if (result == 0)
      return mid;
    else if (result < 0)
      low = mid + 1;
    else
      high = mid - 1;
  }

  return BIP39::UNKNOWN_WORD;
}

/**
 * @brief Derives the 64-byte BIP-39 root seed from a mnemonic sentence.
 *
 * Implements the BIP-39 seed derivation (BIP-0039 §"From mnemonic to seed"):
 *
 *   seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" || passphrase,
 *                             2048 iterations, 64 bytes)
 *
 * The salt is the literal string "mnemonic" concatenated with the optional
 * passphrase. The 2048 iteration count is the BIP-39 mandated value; it is
 * deliberately low enough to keep wallet recovery fast while still providing
 * meaningful key-stretching against offline brute force.
 *
 * @param _mnemonicString the space-separated mnemonic sentence
 * @param password        optional BIP-39 passphrase (may be empty)
 * @return                the 64-byte root seed
 *
 * @note The mnemonic and passphrase are passed through unchanged; NFKD
 *       normalisation is a no-op for the ASCII English wordlist but would be
 *       required for non-ASCII wordlists. The returned seed is the entropy
 *       source for the deterministic RSA key derivation (see
 *       getDeterministicRSAKey()).
 */
BIP39::RootSeedType BIP39::createRootSeed(const std::string &_mnemonicString,
                                          const std::string password) {

  std::string salt = "mnemonic" + password;
  RootSeedType digest{};

  // A PBKDF2 failure would leave the digest zeroed and therefore derive the
  // wallet from a known constant; treat it as fatal.
  if (PKCS5_PBKDF2_HMAC(_mnemonicString.data(), _mnemonicString.size(),
                        (const unsigned char *)salt.data(), salt.size(), 2048,
                        EVP_sha512(), 64,
                        (unsigned char *)digest.data()) != 1)
    throw std::runtime_error(
        std::string("BIP39: PBKDF2 failure: ") +
        ERR_error_string(ERR_get_error(), nullptr));

  return digest;
}

/**
 * @brief Renders the root seed as a lowercase hexadecimal string.
 *
 * Each of the 64 seed bytes is formatted as a zero-padded two-digit lowercase
 * hex pair, producing a 128-character string. This is the canonical textual
 * representation used for logging, test vectors and interoperability checks.
 *
 * @return the hex-encoded root seed
 */
std::string BIP39::getRootSeedAsHex() {

  std::ostringstream ret;
  for (auto &entry : _rootSeed)
    ret << std::hex << std::setfill('0') << std::setw(2)
        << static_cast<unsigned int>(entry);

  return ret.str();
}

// ---------------------------------------------------------------------------
// Deterministic RSA key generation.
//
// DESIGN GOAL: bit-for-bit compatibility with ipfs-shipyard/js-human-crypto-
// keys, the reference implementation used by the Arweave ecosystem to derive
// wallet keys from BIP-39 mnemonics. js-human-crypto-keys does not use
// OpenSSL. It substitutes the PRNG inside node-forge with an HMAC-DRBG
// (SHA-256) seeded from the BIP-39 root seed and leaves forge's prime search
// untouched (algorithm "PRIMEINC", i.e. jsbn's 30k+1 candidate sweep). The
// private key material is therefore a pure function of the seed.
//
// This implementation replays both halves using OpenSSL primitives only
// (HMAC, BIGNUM, EVP). OpenSSL's own keygen API (RSA_generate_key_ex,
// EVP_PKEY_keygen, RAND_bytes) is deliberately not used: it offers no hook to
// inject a caller-supplied DRBG, so it cannot produce the same bytes.
//
// Compatibility invariants (all required; see individual function headers):
//   1. DRBG: K = 0x00.., V = 0x01.., then _update(entropy) with
//      nonce = pers = empty. After each generate() an _update(NULL).
//   2. Draw: (bits >> 3) + 1 bytes, top byte masked with (1 << (bits & 7)) - 1
//      (zeroed when bits is a multiple of 8), then MSB forced and the value
//      aligned to 30k+1.
//   3. Sweep: +6,+4,+2,+4,+2,+4,+6,+2 cyclically; bignum overflow past
//      `bits` aborts the sweep and a fresh draw is taken.
//   4. Filters: candidate must be prime AND gcd(p-1, e) == 1, else redraw.
//   5. Order: p first (bits - (bits >> 1)), then q (bits >> 1), then swap so
//      that p > q. n of the wrong bit length discards q only, keeping p.
//   6. Arithmetic: phi = (p-1)(q-1) (Euler totient, not Carmichael lambda),
//      d = e^-1 mod phi, dP = d mod (p-1), dQ = d mod (q-1), qInv = q^-1 mod p.
// ---------------------------------------------------------------------------

/**
 * @brief Computes HMAC-SHA-256 over @p in keyed with @p key.
 *
 * Thin wrapper over OpenSSL's one-shot HMAC() so the DRBG code expresses
 * intent rather than boilerplate. The digest length is fixed at 32 bytes,
 * which is the HMAC-DRBG output block size mandated by SP 800-90A for the
 * SHA-256 instantiation.
 *
 * @param key    key bytes (always the DRBG chaining key K, 32 bytes)
 * @param keyLen key length in bytes
 * @param in     message to authenticate
 * @param inLen  message length in bytes
 * @param out    destination for the 32-byte digest
 */
static void hmacSha256(const std::uint8_t *key, std::size_t keyLen,
                       const std::uint8_t *in, std::size_t inLen,
                       std::uint8_t *out) {
  unsigned int len = 32;
  HMAC(EVP_sha256(), key, static_cast<int>(keyLen), in, inLen, out, &len);
}

/**
 * @brief Executes the HMAC-DRBG _update() transform (SP 800-90A, as
 *        implemented by indutny/hmac-drbg).
 *
 * Rewrites K and V from @p seed. With @p seed == nullptr only the seedless
 * branch runs, which is what hmac-drbg applies after every generate() call
 * that produced output. The seed corresponds to the concatenation
 * entropy || nonce || pers; in the reference both nonce and pers are always
 * empty, so the seed is the raw entropy.
 *
 * @param seed    seed bytes, or nullptr for the seedless update
 * @param seedLen seed length in bytes (bounded by the internal buffer, 512)
 */
void BIP39::drbgUpdate(const std::uint8_t *seed, std::size_t seedLen) const {
  std::uint8_t buf[32 + 1 + 512], tmp[32];
  std::memcpy(buf, _drbg.V.data(), 32);
  buf[32] = 0x00;
  if (seed) std::memcpy(buf + 32 + 1, seed, seedLen);
  hmacSha256(_drbg.K.data(), 32, buf, 32 + 1 + (seed ? seedLen : 0), tmp);
  std::memcpy(_drbg.K.data(), tmp, 32);
  hmacSha256(_drbg.K.data(), 32, _drbg.V.data(), 32, tmp);
  std::memcpy(_drbg.V.data(), tmp, 32);
  if (!seed) return;
  std::memcpy(buf, _drbg.V.data(), 32);
  buf[32] = 0x01;
  std::memcpy(buf + 32 + 1, seed, seedLen);
  hmacSha256(_drbg.K.data(), 32, buf, 32 + 1 + seedLen, tmp);
  std::memcpy(_drbg.K.data(), tmp, 32);
  hmacSha256(_drbg.K.data(), 32, _drbg.V.data(), 32, tmp);
  std::memcpy(_drbg.V.data(), tmp, 32);
}

/**
 * @brief Initialises the HMAC-DRBG from the BIP-39 root seed.
 *
 * Sets K = 0x00.. and V = 0x01.. (32 bytes each) and immediately applies
 * drbgUpdate() with the seed. This is the hmac-drbg constructor path with a
 * NULL nonce and NULL personalisation string, which makes the generator a
 * pure function of the seed.
 *
 * @param seed the 64-byte BIP-39 root seed; hmac-drbg requires >= 32 bytes
 */
void BIP39::drbgInit(const RootSeedType &seed) const {
  _drbg.K.fill(0x00);
  _drbg.V.fill(0x01);
  drbgUpdate(seed.data(), seed.size());
}

/**
 * @brief Produces @p outLen pseudo-random bytes from the DRBG.
 *
 * Repeatedly applies V = HMAC(K, V), concatenates the outputs and truncates
 * to @p outLen, then performs the seedless drbgUpdate(). This mirrors
 * hmac-drbg generate(count) byte for byte, including the trailing state
 * transition that advances the generator for the next call.
 *
 * @param out    destination buffer, at least @p outLen bytes
 * @param outLen number of bytes requested
 */
void BIP39::drbgGenerate(std::uint8_t *out, std::size_t outLen) const {
  std::size_t done = 0;
  while (done < outLen) {
    std::uint8_t tmp[32];
    hmacSha256(_drbg.K.data(), 32, _drbg.V.data(), 32, tmp);
    std::memcpy(_drbg.V.data(), tmp, 32);
    std::size_t chunk = (outLen - done < 32) ? outLen - done : 32;
    std::memcpy(out + done, _drbg.V.data(), chunk);
    done += chunk;
  }
  drbgUpdate(nullptr, 0);
}

/**
 * @brief Draws a random integer of @p bits bits from the DRBG.
 *
 * Replicates jsbn's `new BigInteger(bits, rng)` constructor: reads
 * (bits >> 3) + 1 bytes and masks the leading byte down to the low
 * (bits & 7) bits, zeroing it entirely when bits is a multiple of 8.
 *
 * The extra byte is not an off-by-one bug to be fixed: jsbn always allocates
 * (bits >> 3) + 1 bytes and then discards whatever the mask removes. Any
 * "cleanup" of this length changes the byte stream and destroys bit
 * compatibility with the reference implementation.
 *
 * @param bits requested bit length
 * @return     freshly allocated BIGNUM (caller frees), nullptr on allocation
 *             failure
 */
BIGNUM *BIP39::randomBits(int bits) const {
  int len = (bits >> 3) + 1, t = bits & 7;
  std::vector<std::uint8_t> buf(static_cast<std::size_t>(len));
  BIGNUM *num;
  drbgGenerate(buf.data(), buf.size());
  if (t > 0)
    buf[0] &= static_cast<std::uint8_t>((1 << t) - 1);
  else
    buf[0] = 0x00;
  num = BN_bin2bn(buf.data(), len, nullptr);
  return num;
}

/**
 * @brief Produces an aligned prime candidate.
 *
 * Mirrors generateRandom() in forge/jsbn: force the MSB, then align the value
 * to the next 30k+1 boundary by adding 31 - (num mod 30). Every prime above
 * 5 sits on one of the eight residues coprime to 30, so the subsequent sweep
 * only has to test 8 out of every 30 integers.
 *
 * @param bits bit length of the candidate
 * @return     new candidate (caller frees), nullptr on allocation failure
 */
BIGNUM *BIP39::randomCandidate(int bits) const {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *num = randomBits(bits), *thirty = BN_new(), *rem = BN_new();
  if (!BN_is_bit_set(num, bits - 1)) BN_set_bit(num, bits - 1);
  BN_set_word(thirty, 30);
  BN_mod(rem, num, thirty, ctx);
  BN_add_word(num, 31 - BN_get_word(rem));
  BN_free(thirty);
  BN_free(rem);
  BN_CTX_free(ctx);
  return num;
}

/**
 * @brief Tests @p n for primality (Miller-Rabin, negligible error
 *        probability).
 *
 * Uses BN_check_prime() on OpenSSL >= 3.0 and BN_is_prime_ex() with the
 * library's size-dependent round count otherwise. Exact round parity with the
 * reference is irrelevant: the composite candidates all fail regardless, and
 * the accepted prime is uniquely determined by the DRBG-driven sequence.
 *
 * @param n   value under test
 * @param ctx scratch BN_CTX
 * @return    true if @p n is probably prime, false otherwise
 */
static bool isPrime(const BIGNUM *n, BN_CTX *ctx) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  return BN_check_prime(n, ctx, nullptr) == 1;
#else
  return BN_is_prime_ex(n, BN_prime_checks_for_size(BN_num_bits(n)), ctx,
                        nullptr) == 1;
#endif
}

/**
 * @brief Tests whether p - 1 is coprime to the public exponent.
 *
 * forge rejects a prime whose predecessor shares a factor with e, since no
 * valid private exponent could be derived from it. Because this rejection
 * happens inside the candidate loop and consumes further DRBG output, it is
 * part of the compatibility contract, not merely a sanity check.
 *
 * @param p   candidate prime
 * @param e   public exponent (normally 65537)
 * @param ctx scratch BN_CTX
 * @return    true if gcd(p - 1, e) == 1, false otherwise
 */
static bool coprimeWithE(const BIGNUM *p, const BIGNUM *e, BN_CTX *ctx) {
  BIGNUM *m1 = BN_dup(p), *g = BN_new();
  BN_sub_word(m1, 1);
  BN_gcd(g, m1, e, ctx);
  bool ok = BN_is_one(g);
  BN_free(g);
  BN_free(m1);
  return ok;
}

/**
 * @brief Searches for an e-compatible prime of @p bits bits (forge
 *        PRIMEINC).
 *
 * Outer loop: draw one aligned candidate via randomCandidate(). Inner loop:
 * walk the candidate along the 30k+1 residue classes using the delta cycle
 * 6,4,2,4,2,4,6,2; a bignum overflow beyond @p bits aborts the walk and
 * forces a fresh draw. A candidate is accepted only when it is prime and
 * gcd(candidate - 1, e) == 1; a prime failing the second test is discarded
 * and also causes a redraw, matching forge exactly.
 *
 * @param bits bit length of the requested prime
 * @param e    public exponent used for the coprime filter
 * @param ctx  scratch BN_CTX
 * @return     accepted prime (caller frees)
 */
BIGNUM *BIP39::findPrime(int bits, const BIGNUM *e, BN_CTX *ctx) const {
  static const unsigned long DELTA[8] = {6, 4, 2, 4, 2, 4, 6, 2};
  for (;;) {
    BIGNUM *num = randomCandidate(bits);
    unsigned long i = 0;
    for (;;) {
      if (BN_num_bits(num) > bits) {
        BN_free(num);
        break;
      }
      if (isPrime(num, ctx)) {
        if (coprimeWithE(num, e, ctx)) return num;
        BN_free(num);
        break;
      }
      BN_add_word(num, DELTA[i++ % 8]);
    }
  }
}

/**
 * @brief Derives a complete RSA key from the root seed (deterministic
 *        keygen).
 *
 * Replays forge's stepKeyPairGenerationState() as a straight-line loop:
 * p is drawn at bit length bits - (bits >> 1), q at bits >> 1, and the two
 * are swapped so that p > q. The retry ladder mirrors forge exactly:
 *
 *   - gcd(phi, e) != 1  -> discard both primes, redraw p and q
 *   - bit length of n != bits -> discard q only, keep p, redraw q
 *
 * On success d = e^-1 mod phi (Euler totient, matching forge), and the CRT
 * parameters dP, dQ and qInv are computed. The exponent e is transferred into
 * the key and must therefore not be freed by the caller.
 *
 * @param key  output key, zeroed first; on failure it is left empty
  * @param seed the entropy source for the HMAC-DRBG (>= 32 bytes)
  * @param bits modulus bit length; must be even
  * @param eInt public exponent, e.g. 65537
  * @return     true on success, false on allocation or modular-inverse failure
  */
 bool BIP39::generateRSAKey(RSAKey &key, const RootSeedType &seed, int bits,
                            unsigned long eInt) const {
   BN_CTX *ctx = BN_CTX_new();
   BIGNUM *e = BN_new(), *p = nullptr, *q = nullptr;

   BN_set_word(e, eInt);
   drbgInit(seed);

  for (;;) {
    BIGNUM *phi, *p1, *q1, *n, *g;

    if (p == nullptr) p = findPrime(bits - (bits >> 1), e, ctx);
    if (q == nullptr) q = findPrime(bits >> 1, e, ctx);
    if (BN_cmp(p, q) < 0) {
      BIGNUM *t = p;
      p = q;
      q = t;
    }

    p1 = BN_dup(p);
    q1 = BN_dup(q);
    BN_sub_word(p1, 1);
    BN_sub_word(q1, 1);

    phi = BN_new();
    BN_mul(phi, p1, q1, ctx);
    g = BN_new();
    BN_gcd(g, phi, e, ctx);
    if (!BN_is_one(g)) { /* phi not coprime to e: redraw p and q */
      BN_free(g);
      BN_free(phi);
      BN_free(p1);
      BN_free(q1);
      BN_free(p);
      BN_free(q);
      p = q = nullptr;
      continue;
    }
    BN_free(g);

    n = BN_new();
    BN_mul(n, p, q, ctx);
    if (BN_num_bits(n) != bits) { /* wrong n size: redraw q only */
      BN_free(n);
      BN_free(phi);
      BN_free(p1);
      BN_free(q1);
      BN_free(q);
      q = nullptr;
      continue;
    }

    BIGNUM *d = BN_mod_inverse(nullptr, e, phi, ctx);
    BIGNUM *dP = BN_new(), *dQ = BN_new(), *qInv = BN_new();
    BN_mod(dP, d, p1, ctx);
    BN_mod(dQ, d, q1, ctx);
    if (BN_mod_inverse(qInv, q, p, ctx) == nullptr) {
      BN_free(phi);
      BN_free(p1);
      BN_free(q1);
      BN_free(d);
      BN_free(dP);
      BN_free(dQ);
      BN_free(qInv);
      BN_free(n);
      BN_free(p);
      BN_free(q);
      BN_free(e);
      BN_CTX_free(ctx);
      return false;
    }

    // Serialise every component as its minimal big-endian magnitude.
    auto toBin = [](const BIGNUM *bn) {
      int len = BN_num_bytes(bn);
      BinaryContainer_t out(static_cast<std::size_t>(len));
      if (len > 0) BN_bn2bin(bn, out.data());
      return out;
    };
    key.n = toBin(n);
    key.e = toBin(e);
    key.d = toBin(d);
    key.p = toBin(p);
    key.q = toBin(q);
    key.dP = toBin(dP);
    key.dQ = toBin(dQ);
    key.qInv = toBin(qInv);

    BN_free(phi);
    BN_free(p1);
    BN_free(q1);
    BN_free(d);
    BN_free(dP);
    BN_free(dQ);
    BN_free(qInv);
    BN_free(n);
    BN_free(p);
    BN_free(q);
    BN_free(e);
    BN_CTX_free(ctx);
    return true;
  }
}

/**
 * @brief Derives the deterministic RSA key from the current root seed.
 *
 * The modulus size defaults to 4096 bits (the Arweave standard) and the
 * public exponent to 65537, matching the reference js-human-crypto-keys
 * defaults. The result is a pure function of the seed: the same mnemonic
 * always reproduces the same key, which is the property that makes wallet
 * recovery from a BIP-39 phrase possible.
 *
 * @return the RSA key components, or an empty RSAKey on failure.
 */
BIP39::RSAKey BIP39::getDeterministicRSAKey() const {
  return getDeterministicRSAKey(_rootSeed);
}

/**
 * @brief Derives the deterministic RSA key from an explicit root seed.
 *
 * This overload allows a caller that already holds a 64-byte BIP-39 root seed
 * (for example a PEM instance recovering a wallet from a seed) to derive the
 * key without first round-tripping through a mnemonic sentence. The derivation
 * is identical to the no-argument overload: the seed seeds the HMAC-DRBG and
 * the forge PRIMEINC sweep runs over 4096-bit moduli with e = 65537.
 *
 * @param seed the 64-byte BIP-39 root seed
 * @return     the RSA key components, or an empty RSAKey on failure
 */
BIP39::RSAKey BIP39::getDeterministicRSAKey(const RootSeedType &seed) const {
  RSAKey key;
  if (!generateRSAKey(key, seed, 4096, 65537)) return RSAKey{};
  return key;
}

} // end of namespace crypto
} // namespace artools