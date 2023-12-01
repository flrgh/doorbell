use maxminddb::{MaxMindDBError, geoip2};

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    serde_derive::Deserialize,
    serde_derive::Serialize,
    sqlx::Type,
    strum_macros::AsRefStr,
    strum_macros::Display,
    strum_macros::EnumString,
)]
#[strum(serialize_all = "UPPERCASE")]
#[sqlx(rename_all = "UPPERCASE")]
pub enum CountryCode {
    AD,
    AE,
    AF,
    AG,
    AI,
    AL,
    AM,
    AO,
    AQ,
    AR,
    AS,
    AT,
    AU,
    AW,
    AX,
    AZ,
    BA,
    BB,
    BD,
    BE,
    BF,
    BG,
    BH,
    BI,
    BJ,
    BL,
    BM,
    BN,
    BO,
    BQ,
    BR,
    BS,
    BT,
    BV,
    BW,
    BY,
    BZ,
    CA,
    CC,
    CD,
    CF,
    CG,
    CH,
    CI,
    CK,
    CL,
    CM,
    CN,
    CO,
    CR,
    CU,
    CV,
    CW,
    CX,
    CY,
    CZ,
    DE,
    DJ,
    DK,
    DM,
    DO,
    DZ,
    EC,
    EE,
    EG,
    EH,
    ER,
    ES,
    ET,
    FI,
    FJ,
    FK,
    FM,
    FO,
    FR,
    GA,
    GB,
    GD,
    GE,
    GF,
    GG,
    GH,
    GI,
    GL,
    GM,
    GN,
    GP,
    GQ,
    GR,
    GS,
    GT,
    GU,
    GW,
    GY,
    HK,
    HM,
    HN,
    HR,
    HT,
    HU,
    ID,
    IE,
    IL,
    IM,
    IN,
    IO,
    IQ,
    IR,
    IS,
    IT,
    JE,
    JM,
    JO,
    JP,
    KE,
    KG,
    KH,
    KI,
    KM,
    KN,
    KP,
    KR,
    KW,
    KY,
    KZ,
    LA,
    LB,
    LC,
    LI,
    LK,
    LR,
    LS,
    LT,
    LU,
    LV,
    LY,
    MA,
    MC,
    MD,
    ME,
    MF,
    MG,
    MH,
    MK,
    ML,
    MM,
    MN,
    MO,
    MP,
    MQ,
    MR,
    MS,
    MT,
    MU,
    MV,
    MW,
    MX,
    MY,
    MZ,
    NA,
    NC,
    NE,
    NF,
    NG,
    NI,
    NL,
    NO,
    NP,
    NR,
    NU,
    NZ,
    OM,
    PA,
    PE,
    PF,
    PG,
    PH,
    PK,
    PL,
    PM,
    PN,
    PR,
    PS,
    PT,
    PW,
    PY,
    QA,
    RE,
    RO,
    RS,
    RU,
    RW,
    SA,
    SB,
    SC,
    SD,
    SE,
    SG,
    SH,
    SI,
    SJ,
    SK,
    SL,
    SM,
    SN,
    SO,
    SR,
    SS,
    ST,
    SV,
    SX,
    SY,
    SZ,
    TC,
    TD,
    TF,
    TG,
    TH,
    TJ,
    TK,
    TL,
    TM,
    TN,
    TO,
    TR,
    TT,
    TV,
    TW,
    TZ,
    UA,
    UG,
    UM,
    US,
    UY,
    UZ,
    VA,
    VC,
    VE,
    VG,
    VI,
    VN,
    VU,
    WF,
    WS,
    XK,
    YE,
    YT,
    ZA,
    ZM,
    ZW,
}

impl CountryCode {
    pub fn name(&self) -> &'static str {
        match self {
            Self::AD => "Andorra",
            Self::AE => "United Arab Emirates",
            Self::AF => "Afghanistan",
            Self::AG => "Antigua and Barbuda",
            Self::AI => "Anguilla",
            Self::AL => "Albania",
            Self::AM => "Armenia",
            Self::AO => "Angola",
            Self::AQ => "Antarctica",
            Self::AR => "Argentina",
            Self::AS => "American Samoa",
            Self::AT => "Austria",
            Self::AU => "Australia",
            Self::AW => "Aruba",
            Self::AX => "Aland Islands",
            Self::AZ => "Azerbaijan",
            Self::BA => "Bosnia and Herzegovina",
            Self::BB => "Barbados",
            Self::BD => "Bangladesh",
            Self::BE => "Belgium",
            Self::BF => "Burkina Faso",
            Self::BG => "Bulgaria",
            Self::BH => "Bahrain",
            Self::BI => "Burundi",
            Self::BJ => "Benin",
            Self::BL => "Saint Barthelemy",
            Self::BM => "Bermuda",
            Self::BN => "Brunei",
            Self::BO => "Bolivia",
            Self::BQ => "Bonaire, Saint Eustatius and Saba ",
            Self::BR => "Brazil",
            Self::BS => "Bahamas",
            Self::BT => "Bhutan",
            Self::BV => "Bouvet Island",
            Self::BW => "Botswana",
            Self::BY => "Belarus",
            Self::BZ => "Belize",
            Self::CA => "Canada",
            Self::CC => "Cocos Islands",
            Self::CD => "Democratic Republic of the Congo",
            Self::CF => "Central African Republic",
            Self::CG => "Republic of the Congo",
            Self::CH => "Switzerland",
            Self::CI => "Ivory Coast",
            Self::CK => "Cook Islands",
            Self::CL => "Chile",
            Self::CM => "Cameroon",
            Self::CN => "China",
            Self::CO => "Colombia",
            Self::CR => "Costa Rica",
            Self::CU => "Cuba",
            Self::CV => "Cape Verde",
            Self::CW => "Curacao",
            Self::CX => "Christmas Island",
            Self::CY => "Cyprus",
            Self::CZ => "Czech Republic",
            Self::DE => "Germany",
            Self::DJ => "Djibouti",
            Self::DK => "Denmark",
            Self::DM => "Dominica",
            Self::DO => "Dominican Republic",
            Self::DZ => "Algeria",
            Self::EC => "Ecuador",
            Self::EE => "Estonia",
            Self::EG => "Egypt",
            Self::EH => "Western Sahara",
            Self::ER => "Eritrea",
            Self::ES => "Spain",
            Self::ET => "Ethiopia",
            Self::FI => "Finland",
            Self::FJ => "Fiji",
            Self::FK => "Falkland Islands",
            Self::FM => "Micronesia",
            Self::FO => "Faroe Islands",
            Self::FR => "France",
            Self::GA => "Gabon",
            Self::GB => "United Kingdom",
            Self::GD => "Grenada",
            Self::GE => "Georgia",
            Self::GF => "French Guiana",
            Self::GG => "Guernsey",
            Self::GH => "Ghana",
            Self::GI => "Gibraltar",
            Self::GL => "Greenland",
            Self::GM => "Gambia",
            Self::GN => "Guinea",
            Self::GP => "Guadeloupe",
            Self::GQ => "Equatorial Guinea",
            Self::GR => "Greece",
            Self::GS => "South Georgia and the South Sandwich Islands",
            Self::GT => "Guatemala",
            Self::GU => "Guam",
            Self::GW => "Guinea-Bissau",
            Self::GY => "Guyana",
            Self::HK => "Hong Kong",
            Self::HM => "Heard Island and McDonald Islands",
            Self::HN => "Honduras",
            Self::HR => "Croatia",
            Self::HT => "Haiti",
            Self::HU => "Hungary",
            Self::ID => "Indonesia",
            Self::IE => "Ireland",
            Self::IL => "Israel",
            Self::IM => "Isle of Man",
            Self::IN => "India",
            Self::IO => "British Indian Ocean Territory",
            Self::IQ => "Iraq",
            Self::IR => "Iran",
            Self::IS => "Iceland",
            Self::IT => "Italy",
            Self::JE => "Jersey",
            Self::JM => "Jamaica",
            Self::JO => "Jordan",
            Self::JP => "Japan",
            Self::KE => "Kenya",
            Self::KG => "Kyrgyzstan",
            Self::KH => "Cambodia",
            Self::KI => "Kiribati",
            Self::KM => "Comoros",
            Self::KN => "Saint Kitts and Nevis",
            Self::KP => "North Korea",
            Self::KR => "South Korea",
            Self::KW => "Kuwait",
            Self::KY => "Cayman Islands",
            Self::KZ => "Kazakhstan",
            Self::LA => "Laos",
            Self::LB => "Lebanon",
            Self::LC => "Saint Lucia",
            Self::LI => "Liechtenstein",
            Self::LK => "Sri Lanka",
            Self::LR => "Liberia",
            Self::LS => "Lesotho",
            Self::LT => "Lithuania",
            Self::LU => "Luxembourg",
            Self::LV => "Latvia",
            Self::LY => "Libya",
            Self::MA => "Morocco",
            Self::MC => "Monaco",
            Self::MD => "Moldova",
            Self::ME => "Montenegro",
            Self::MF => "Saint Martin",
            Self::MG => "Madagascar",
            Self::MH => "Marshall Islands",
            Self::MK => "Macedonia",
            Self::ML => "Mali",
            Self::MM => "Myanmar",
            Self::MN => "Mongolia",
            Self::MO => "Macao",
            Self::MP => "Northern Mariana Islands",
            Self::MQ => "Martinique",
            Self::MR => "Mauritania",
            Self::MS => "Montserrat",
            Self::MT => "Malta",
            Self::MU => "Mauritius",
            Self::MV => "Maldives",
            Self::MW => "Malawi",
            Self::MX => "Mexico",
            Self::MY => "Malaysia",
            Self::MZ => "Mozambique",
            Self::NA => "Namibia",
            Self::NC => "New Caledonia",
            Self::NE => "Niger",
            Self::NF => "Norfolk Island",
            Self::NG => "Nigeria",
            Self::NI => "Nicaragua",
            Self::NL => "Netherlands",
            Self::NO => "Norway",
            Self::NP => "Nepal",
            Self::NR => "Nauru",
            Self::NU => "Niue",
            Self::NZ => "New Zealand",
            Self::OM => "Oman",
            Self::PA => "Panama",
            Self::PE => "Peru",
            Self::PF => "French Polynesia",
            Self::PG => "Papua New Guinea",
            Self::PH => "Philippines",
            Self::PK => "Pakistan",
            Self::PL => "Poland",
            Self::PM => "Saint Pierre and Miquelon",
            Self::PN => "Pitcairn",
            Self::PR => "Puerto Rico",
            Self::PS => "Palestinian Territory",
            Self::PT => "Portugal",
            Self::PW => "Palau",
            Self::PY => "Paraguay",
            Self::QA => "Qatar",
            Self::RE => "Reunion",
            Self::RO => "Romania",
            Self::RS => "Serbia",
            Self::RU => "Russia",
            Self::RW => "Rwanda",
            Self::SA => "Saudi Arabia",
            Self::SB => "Solomon Islands",
            Self::SC => "Seychelles",
            Self::SD => "Sudan",
            Self::SE => "Sweden",
            Self::SG => "Singapore",
            Self::SH => "Saint Helena",
            Self::SI => "Slovenia",
            Self::SJ => "Svalbard and Jan Mayen",
            Self::SK => "Slovakia",
            Self::SL => "Sierra Leone",
            Self::SM => "San Marino",
            Self::SN => "Senegal",
            Self::SO => "Somalia",
            Self::SR => "Suriname",
            Self::SS => "South Sudan",
            Self::ST => "Sao Tome and Principe",
            Self::SV => "El Salvador",
            Self::SX => "Sint Maarten",
            Self::SY => "Syria",
            Self::SZ => "Swaziland",
            Self::TC => "Turks and Caicos Islands",
            Self::TD => "Chad",
            Self::TF => "French Southern Territories",
            Self::TG => "Togo",
            Self::TH => "Thailand",
            Self::TJ => "Tajikistan",
            Self::TK => "Tokelau",
            Self::TL => "East Timor",
            Self::TM => "Turkmenistan",
            Self::TN => "Tunisia",
            Self::TO => "Tonga",
            Self::TR => "Turkey",
            Self::TT => "Trinidad and Tobago",
            Self::TV => "Tuvalu",
            Self::TW => "Taiwan",
            Self::TZ => "Tanzania",
            Self::UA => "Ukraine",
            Self::UG => "Uganda",
            Self::UM => "United States Minor Outlying Islands",
            Self::US => "United States",
            Self::UY => "Uruguay",
            Self::UZ => "Uzbekistan",
            Self::VA => "Vatican",
            Self::VC => "Saint Vincent and the Grenadines",
            Self::VE => "Venezuela",
            Self::VG => "British Virgin Islands",
            Self::VI => "U.S. Virgin Islands",
            Self::VN => "Vietnam",
            Self::VU => "Vanuatu",
            Self::WF => "Wallis and Futuna",
            Self::WS => "Samoa",
            Self::XK => "Kosovo",
            Self::YE => "Yemen",
            Self::YT => "Mayotte",
            Self::ZA => "South Africa",
            Self::ZM => "Zambia",
            Self::ZW => "Zimbabwe",
        }
    }
}

impl AsRef<[u8]> for CountryCode {
    fn as_ref(&self) -> &[u8] {
        let s: &str = self.as_ref();
        s.as_bytes()
    }
}

pub struct GeoIp {
    path: std::path::PathBuf,
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoIp {
    pub fn new(path: &std::path::Path) -> Result<Self, MaxMindDBError> {
        let reader = maxminddb::Reader::open_readfile(path)?;
        let path = path.to_path_buf();
        Ok(Self { path, reader })
    }

    pub fn reopen(&mut self) -> Result<(), MaxMindDBError> {
        self.reader = maxminddb::Reader::open_readfile(&self.path)?;
        Ok(())
    }

    pub fn lookup_country_code(&self, addr: std::net::IpAddr) -> Result<Option<CountryCode>, MaxMindDBError> {
        let data: geoip2::Country = self.reader.lookup(addr)?;
        let Some(country) = data.country else {
            return Ok(None);
        };

        let Some(code) = country.iso_code else {
            return Ok(None);
        };

        match CountryCode::try_from(code) {
            Ok(cc) => Ok(Some(cc)),
            Err(_) => Ok(None),
        }
    }
}
