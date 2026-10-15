//! MIT's SPAKE test vectors (`src/plugins/preauth/spake/t_vectors.c`,
//! which are draft-ietf-kitten-krb-spake-preauth's), for the AES
//! enctypes: w, both sides' results, the transcript hash and `K'[0..3]`.

use super::*;

struct V {
    etype: i32,
    group: SpakeGroup,
    ikey: &'static str,
    w: &'static str,
    /// The KDC's private scalar, and its public value T (in the challenge).
    x: &'static str,
    /// The client's private scalar, and its public value S.
    y: &'static str,
    t: &'static str,
    s: &'static str,
    k: &'static str,
    support: Option<&'static str>,
    challenge: &'static str,
    thash: &'static str,
    body: &'static str,
    k0: &'static str,
    k1: &'static str,
    k2: &'static str,
    k3: &'static str,
}

const VECTORS: &[V] = &[
    V {
        etype: 17,
        group: SpakeGroup::Edwards25519,
        ikey: "FCA822951813FB252154C883F5EE1CF4",
        w: "0D591B197B667E083C2F5F98AC891D3C9F99E710E464E62F1FB7C9B67936F3EB",
        x: "50BE049A5A570FA1459FB9F666E6FD80602E4E87790A0E567F12438A2C96C138",
        y: "B877AFE8612B406D96BE85BD9F19D423E95BE96C0E1E0B5824127195C3ED5917",
        t: "9E9311D985C1355E022D7C3C694AD8D6F7AD6D647B68A90B0FE46992818002DA",
        s: "FBE08F7F96CD5D4139E7C9ECCB95E79B8ACE41E270A60198C007DF18525B628E",
        k: "C2F7F99997C585E6B686CEB62DB42F17CC70932DEF3BB4CF009E36F22EA5473D",
        support: Some("A0093007A0053003020101"),
        challenge: concat!(
            "A1363034A003020101A12204209E9311D985C1355E022D7C3C694AD8D6F7AD6D",
            "647B68A90B0FE46992818002DAA20930073005A003020101",
        ),
        thash: "951285F107C87F0169B9C918A1F51F60CB1A75B9F8BB799A99F53D03ADD94B5F",
        body: concat!(
            "3075A00703050000000000A1143012A003020101A10B30091B07726165627572",
            "6EA2101B0E415448454E412E4D49542E454455A3233021A003020102A11A3018",
            "1B066B72627467741B0E415448454E412E4D49542E454455A511180F31393730",
            "303130313030303030305AA703020100A8053003020111",
        ),
        k0: "548022D58A7C47EAE8C49DCCF6BAA407",
        k1: "B2C9BA0E13FC8AB3A9D96B51B601CF4A",
        k2: "69F0EE5FDB6C237E7FCD38D9F87DF1BD",
        k3: "78F91E2240B5EE528A5CC8D7CBEBFBA5",
    },
    V {
        etype: 18,
        group: SpakeGroup::Edwards25519,
        ikey: "01B897121D933AB44B47EB5494DB15E50EB74530DBDAE9B634D65020FF5D88C1",
        w: "E902341590A1B4BB4D606A1C643CCCB3F2108F1B6AA97B381012B9400C9E3F4E",
        x: "88C6C0A4F0241EF217C9788F02C32D00B72E4310748CD8FB5F94717607E6417D",
        y: "88B859DF58EF5C69BACDFE681C582754EAAB09A74DC29CFF50B328613C232F55",
        t: "6F301AACAE1220E91BE42868C163C5009AEEA1E9D9E28AFCFC339CDA5E7105B5",
        s: "9E2CC32908FC46273279EC75354B4AEAFA70C3D99A4D507175ED70D80B255DDA",
        k: "CF57F58F6E60169D2ECC8F20BB923A8E4C16E5BC95B9E64B5DC870DA7026321B",
        support: Some("A0093007A0053003020101"),
        challenge: concat!(
            "A1363034A003020101A12204206F301AACAE1220E91BE42868C163C5009AEEA1",
            "E9D9E28AFCFC339CDA5E7105B5A20930073005A003020101",
        ),
        thash: "1C605649D4658B58CBE79A5FAF227ACC16C355C58B7DADE022F90C158FE5ED8E",
        body: concat!(
            "3075A00703050000000000A1143012A003020101A10B30091B07726165627572",
            "6EA2101B0E415448454E412E4D49542E454455A3233021A003020102A11A3018",
            "1B066B72627467741B0E415448454E412E4D49542E454455A511180F31393730",
            "303130313030303030305AA703020100A8053003020112",
        ),
        k0: "A9BFA71C95C575756F922871524B65288B3F695573CCC0633E87449568210C23",
        k1: "1865A9EE1EF0640EC28AC007391CAC624C42639C714767A974E99AA10003015F",
        k2: "E57781513FEFDB978E374E156B0DA0C1A08148F5EB26B8E157AC3C077E28BF49",
        k3: "008E6487293C3CC9FABBBCDD8B392D6DCB88222317FD7FE52D12FBC44FA047F1",
    },
    #[cfg(feature = "spake-nist")]
    V {
        etype: 18,
        group: SpakeGroup::P256,
        ikey: "01B897121D933AB44B47EB5494DB15E50EB74530DBDAE9B634D65020FF5D88C1",
        w: "EB2984AF18703F94DD5288B8596CD36988D0D4E83BFB2B44DE14D0E95E2090BD",
        x: "935DDD725129FB7C6288E1A5CC45782198A6416D1775336D71EACD0549A3E80E",
        y: "E07405EB215663ABC1F254B8ADC0DA7A16FEBAA011AF923D79FDEF7C42930B33",
        t: concat!(
            "024F62078CEB53840D02612195494D0D0D88DE21FEEB81187C71CBF3D01E7178",
            "8D",
        ),
        s: concat!(
            "021D07DC31266FC7CFD904CE2632111A169B7EC730E5F74A7E79700F86638E13",
            "C8",
        ),
        k: concat!(
            "0268489D7A9983F2FDE69C6E6A1307E9D252259264F5F2DFC32F58CCA19671E7",
            "9B",
        ),
        support: Some("A0093007A0053003020102"),
        challenge: concat!(
            "A1373035A003020102A1230421024F62078CEB53840D02612195494D0D0D88DE",
            "21FEEB81187C71CBF3D01E71788DA20930073005A003020101",
        ),
        thash: "20AD3C1A9A90FC037D1963A1C4BFB15AB4484D7B6CF07B12D24984F14652DE60",
        body: concat!(
            "3075A00703050000000000A1143012A003020101A10B30091B07726165627572",
            "6EA2101B0E415448454E412E4D49542E454455A3233021A003020102A11A3018",
            "1B066B72627467741B0E415448454E412E4D49542E454455A511180F31393730",
            "303130313030303030305AA703020100A8053003020112",
        ),
        k0: "7D3B906F7BE49932DB22CD3463F032D06C9C078BE4B1D076D201FC6E61EF531E",
        k1: "17D74E36F8993841FBB7FEB12FA4F011243D3AE4D2ACE55B39379294BBC4DB2C",
        k2: "D192C9044081A2AA6A97A6C69E2724E8E5671C2C9CE073DD439CDBAF96D7DAB0",
        k3: "41E5BAD6B67F12C53CE0E2720DD6A9887F877BF9463C2D5209C74C36F8D776B7",
    },
    #[cfg(feature = "spake-nist")]
    V {
        etype: 18,
        group: SpakeGroup::P384,
        ikey: "01B897121D933AB44B47EB5494DB15E50EB74530DBDAE9B634D65020FF5D88C1",
        w: concat!(
            "0304CFC55151C6BBE889653DB96DBFE0BA4ACAFC024C1E8840CB3A486F6D80C1",
            "6E1B8974016AA4B7FA43042A9B3825B1",
        ),
        x: concat!(
            "F323CA74D344749096FD35D0ADF20806E521460637176E84D977E9933C49D76F",
            "CFC6E62585940927468FF53D864A7A50",
        ),
        y: concat!(
            "5B7C709ACB175A5AFB82860DEABCA8D0B341FACDFF0AC0F1A425799AA905D750",
            "7E1EA9C573581A81467437419466E472",
        ),
        t: concat!(
            "02A1524603EF14F184696F854229D3397507A66C63F841BA748451056BE07879",
            "AC298912387B1C5CDFF6381C264701BE57",
        ),
        s: concat!(
            "020D5ADFDB92BC377041CF5837412574C5D13E0F4739208A4F0C859A0A302BC6",
            "A533440A245B9D97A0D34AF5016A20053D",
        ),
        k: concat!(
            "0264AA8C61DA9600DFB0BEB5E46550D63740E4EF29E73F1A30D543EB43C25499",
            "037AD16538586552761B093CF0E37C703A",
        ),
        support: Some("A0093007A0053003020103"),
        challenge: concat!(
            "A1473045A003020103A133043102A1524603EF14F184696F854229D3397507A6",
            "6C63F841BA748451056BE07879AC298912387B1C5CDFF6381C264701BE57A209",
            "30073005A003020101",
        ),
        thash: concat!(
            "5AC0D99EF9E5A73998797FE64F074673E3952DEC4C7D1AACCE8B75F64D2B0276",
            "A901CB8539B4E8ED69E4DB0CE805B47B",
        ),
        body: concat!(
            "3075A00703050000000000A1143012A003020101A10B30091B07726165627572",
            "6EA2101B0E415448454E412E4D49542E454455A3233021A003020102A11A3018",
            "1B066B72627467741B0E415448454E412E4D49542E454455A511180F31393730",
            "303130313030303030305AA703020100A8053003020112",
        ),
        k0: "B917D37C16DD1D8567FBE379F64E1EE36CA3FD127AA4E60F97E4AFA3D9E56D91",
        k1: "93D40079DAB229B9C79366829F4E7E7282E6A4B943AC7BAC69922D516673F49A",
        k2: "BFC4F16F12F683E71589F9A888E232875EF293AC9793DB6C919567CD7B94BCD4",
        k3: "3630E2B5B99938E7506733141E8EC344166F6407E5FC2EF107C156E764D1BC20",
    },
    #[cfg(feature = "spake-nist")]
    V {
        etype: 18,
        group: SpakeGroup::P521,
        ikey: "01B897121D933AB44B47EB5494DB15E50EB74530DBDAE9B634D65020FF5D88C1",
        w: concat!(
            "DE3A095A2B2386EFF3EB15B735398DA1CAF95BC8425665D82370AFF58B0471F3",
            "4A57BCCDDF1EBF0A2965B58A93EE5B45E85D1A5435D1C8C83662999722D54283",
            "1F9A",
        ),
        x: concat!(
            "017C38701A14B490B6081DFC83524562BE7FBB42E0B20426465E3E37952D30BC",
            "AB0ED857010255D44936A1515607964A870C7C879B741D878F9F9CDF5A865306",
            "F3F5",
        ),
        y: concat!(
            "003E2E2950656FA231E959ACDD984D125E7FA59CEC98126CBC8F3888447911EB",
            "CD49428A1C22D5FDB76A19FBEB1D9EDFA3DA6CF55B158B53031D05D51433ADE9",
            "B2B4",
        ),
        t: concat!(
            "02017D3DE19A3EC53D0174905665EF37947D142535102CD9809C0DFBD0DFE007",
            "353D54CF406CE2A59950F2BB540DF6FBE75F8BBBEF811C9BA06CC275ADBD9675",
            "6696EC",
        ),
        s: concat!(
            "02004D142D87477841F6BA053C8F651F3395AD264B7405CA5911FB9A55ABD454",
            "FEF658A5F9ED97D1EFAC68764E9092FA15B9E0050880D78E95FD03ABF5931791",
            "6822B5",
        ),
        k: concat!(
            "03007C303F62F09282CC849490805BD4457A6793A832CBEB55DF427DB6A31E99",
            "B055D5DC99756D24D47B70AD8B6015B0FB8742A718462ED423B90FA3FE631AC1",
            "3FA916",
        ),
        support: Some("A0093007A0053003020104"),
        challenge: concat!(
            "A1593057A003020104A145044302017D3DE19A3EC53D0174905665EF37947D14",
            "2535102CD9809C0DFBD0DFE007353D54CF406CE2A59950F2BB540DF6FBE75F8B",
            "BBEF811C9BA06CC275ADBD96756696ECA20930073005A003020101",
        ),
        thash: concat!(
            "8D6A89AE4D80CC4E47B6F4E48EA3E57919CC69598D0D3DC7C8BD49B6F1DB1409",
            "CA0312944CD964E213ABA98537041102237CFF5B331E5347A0673869B412302E",
        ),
        body: concat!(
            "3075A00703050000000000A1143012A003020101A10B30091B07726165627572",
            "6EA2101B0E415448454E412E4D49542E454455A3233021A003020102A11A3018",
            "1B066B72627467741B0E415448454E412E4D49542E454455A511180F31393730",
            "303130313030303030305AA703020100A8053003020112",
        ),
        k0: "1EB3D10BEE8FAB483ADCD3EB38F3EBF1F4FEB8DB96ECC035F563CF2E1115D276",
        k1: "482B92781CE57F49176E4C94153CC622FE247A7DBE931D1478315F856F085890",
        k2: "A2C215126DD3DF280AAB5A27E1E0FB7E594192CBFF8D6D8E1B6F1818D9BB8FAC",
        k3: "CC06603DE984324013A01F888DE6D43B410A4DA2DEA53509F30E433C352FB668",
    },
    V {
        etype: 18,
        group: SpakeGroup::Edwards25519,
        ikey: "01B897121D933AB44B47EB5494DB15E50EB74530DBDAE9B634D65020FF5D88C1",
        w: "E902341590A1B4BB4D606A1C643CCCB3F2108F1B6AA97B381012B9400C9E3F4E",
        x: "70937207344CAFBC53C8A55070E399C584CBAFCE00B836980DD4E7E74FAD2A64",
        y: "785D6801A2490DF028903AC6449B105F2FF0DB895B252953CDC2076649526103",
        t: "83523B35F1565006CBFC4F159885467C2FB9BC6FE23D36CB1DA43D199F1A3118",
        s: "2A8F70F46CEE9030700037B77F22CEC7970DCC238E3E066D9D726BAF183992C6",
        k: "D3C5E4266AA6D1B2873A97CE8AF91C7E4D7A7AC456ACCED7908D34C561AD8FA6",
        support: None,
        challenge: concat!(
            "A1363034A003020101A122042083523B35F1565006CBFC4F159885467C2FB9BC",
            "6FE23D36CB1DA43D199F1A3118A20930073005A003020101",
        ),
        thash: "26F07F9F8965307434D11EA855461D41E0CBABCC0A1BAB48ECEE0C6C1A4292B7",
        body: concat!(
            "3075A00703050000000000A1143012A003020101A10B30091B07726165627572",
            "6EA2101B0E415448454E412E4D49542E454455A3233021A003020102A11A3018",
            "1B066B72627467741B0E415448454E412E4D49542E454455A511180F31393730",
            "303130313030303030305AA703020100A8053003020112",
        ),
        k0: "4569EC08B5DE5C3CC19D941725913ACE8D74524B521A341DC746ACD5C3784D92",
        k1: "0D96CE1A4AC0F2E280A0CFC31742B06461D83D04AE45433DB2D80478DD882A4C",
        k2: "58018C19315A1BA5D5BB9813B58029F0AEC18A6F9CA59E0847DE1C60BC25945C",
        k3: "ED7E9BFFD68C54D86FB19CD3C03F317F88A71AD9A5E94C28581D93FC4EC72B6A",
    },
    #[cfg(feature = "spake-nist")]
    V {
        etype: 18,
        group: SpakeGroup::P521,
        ikey: "01B897121D933AB44B47EB5494DB15E50EB74530DBDAE9B634D65020FF5D88C1",
        w: concat!(
            "DE3A095A2B2386EFF3EB15B735398DA1CAF95BC8425665D82370AFF58B0471F3",
            "4A57BCCDDF1EBF0A2965B58A93EE5B45E85D1A5435D1C8C83662999722D54283",
            "1F9A",
        ),
        x: concat!(
            "01687B59051BF40048D7C31D5A973D792FA12284B7A447E7F5938B5885CA0BB2",
            "C3F0BD30291A55FEA08E143E2E04BDD7D19B753C7C99032F06CAB0D9C2AA8F83",
            "7EF7",
        ),
        y: concat!(
            "01DED675EBF74FE30C9A53710F577E9CF84F09F6048FE245A4600004884CC167",
            "733F9A9E43108FB83BABE8754CD37CBD7025E28BC9FF870F084C7244F536285E",
            "25B4",
        ),
        t: concat!(
            "02014CB2E5B592ECE5990F0EF30D308C061DE1598BC4272B4A6599BED466FD15",
            "21693642ABCF4DBE36CE1A2D13967DE45F6C4F8D0FA8E14428BF03FB96EF5F1E",
            "D3E645",
        ),
        s: concat!(
            "02016C64995E804416F748FD5FA3AA678CBC7CBB596A4F523132DC8AF7CE84E5",
            "41F484A2C74808C6B21DCF7775BAEFA6753398425BECC7B838B210AC5DAA0CB0",
            "B710E2",
        ),
        k: concat!(
            "0200997F4848AE2E7A98C23D14AC662030743AB37FCCC2A45F1C721114F40BCC",
            "80FE6EC6ABA49868F8AEA1AA994D50E81B86D3E4D3C1130C8695B68907C673D9",
            "E5886A",
        ),
        support: Some("A0093007A0053003020104"),
        challenge: concat!(
            "A1593057A003020104A145044302014CB2E5B592ECE5990F0EF30D308C061DE1",
            "598BC4272B4A6599BED466FD1521693642ABCF4DBE36CE1A2D13967DE45F6C4F",
            "8D0FA8E14428BF03FB96EF5F1ED3E645A20930073005A003020101",
        ),
        thash: concat!(
            "D0EFED5E3E2C39C26034756D92A66FEC3082AD793D0197F3F89AD36026F146A3",
            "996E548AA3FC49E2E82F8CAC5D132C505AA475B39E7BE79CDED22C26C41AA777",
        ),
        body: concat!(
            "3075A00703050000000000A1143012A003020101A10B30091B07726165627572",
            "6EA2101B0E415448454E412E4D49542E454455A3233021A003020102A11A3018",
            "1B066B72627467741B0E415448454E412E4D49542E454455A511180F31393730",
            "303130313030303030305AA703020100A8053003020112",
        ),
        k0: "631FCC8596E7F40E59045950D72AA0B7BAC2810A07B767050E983841CF3A2D4C",
        k1: "881464920117074DBC67155A8F3341D1121EF65F78EA0380BFA81A134C1C47B1",
        k2: "377B72AC3AF2CAAD582D73AE4682FD56B531EE56706200DD6C38C42B8219837A",
        k3: "35AD8E4D580ED3F0D15AD928329773C081BD19F9A56363F3A5F77C7E66108C26",
    },
];

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn mits_vectors() {
    for (i, v) in VECTORS.iter().enumerate() {
        let g = v.group;
        let ikey = Key::new(v.etype, hex(v.ikey)).unwrap();
        let w = wbytes(g, &ikey).unwrap();
        assert_eq!(w, hex(v.w), "{i}: w");
        // The KDC's T = x·G + w·M and the client's S = y·G + w·N.
        assert_eq!(
            g.public(&w, &hex(v.x), Mask::M).unwrap(),
            hex(v.t),
            "{i}: T"
        );
        assert_eq!(
            g.public(&w, &hex(v.y), Mask::N).unwrap(),
            hex(v.s),
            "{i}: S"
        );
        // K from both ends.
        assert_eq!(
            g.result(&w, &hex(v.x), &hex(v.s), Mask::N).unwrap(),
            hex(v.k),
            "{i}: KDC K"
        );
        assert_eq!(
            g.result(&w, &hex(v.y), &hex(v.t), Mask::M).unwrap(),
            hex(v.k),
            "{i}: client K"
        );
        // Our parse of the challenge, and our support message.
        let ch = parse_challenge(&hex(v.challenge)).unwrap().unwrap();
        assert_eq!(
            (ch.group, ch.pubkey.clone(), ch.factors.clone()),
            (g.id(), hex(v.t), vec![1])
        );
        if let Some(sup) = v.support {
            assert_eq!(support_message(&[g]), hex(sup), "{i}: support");
        }
        let zeros = vec![0u8; g.hash_len()];
        let support = v.support.map(hex).unwrap_or_default();
        let thash = update_thash(g, &zeros, &support, &hex(v.challenge));
        let thash = update_thash(g, &thash, &hex(v.s), &[]);
        assert_eq!(thash, hex(v.thash), "{i}: thash");
        for (n, want) in [v.k0, v.k1, v.k2, v.k3].into_iter().enumerate() {
            let k = derive_key(g, &ikey, &w, &hex(v.k), &thash, &hex(v.body), n as u32).unwrap();
            assert_eq!(k.bytes(), hex(want), "{i}: K'[{n}]");
        }
    }
}

/// A challenge with only these second factors, in `group`.
fn challenge(group: i32, factors: &[i64]) -> Vec<u8> {
    let f: Vec<Vec<u8>> = factors
        .iter()
        .map(|&t| der::seq(&[der::field(0, der::int(t))]))
        .collect();
    der::field(
        1,
        der::seq(&[
            der::field(0, der::int(i64::from(group))),
            der::field(1, der::octets(&ed25519::Point::base().encode())),
            der::field(2, der::seq(&f)),
        ]),
    )
}

#[test]
fn the_client_side_conversation() {
    let ed = [SpakeGroup::Edwards25519];
    let ikey = || Key::random(18).unwrap();
    // Offered without a challenge: our support message.
    let mut s = Spake::default();
    match s.step(&ed, &[], ikey()).unwrap() {
        Step::Send(m) => assert_eq!(m, support_message(&ed)),
        Step::Respond => panic!("nothing to respond to"),
    }
    assert!(s.support_sent());
    // Then the challenge: answered in the next request, with K'[0].
    assert!(matches!(
        s.step(&ed, &challenge(1, &[1]), ikey()).unwrap(),
        Step::Respond
    ));
    let (resp, k0) = s.respond(b"body").unwrap().unwrap();
    assert_eq!(resp[0], der::ctx(2), "SPAKEResponse");
    assert_eq!(k0.enctype(), 18);
    assert!(s.responded() && !s.support_sent());
    assert!(s.respond(b"body").unwrap().is_none(), "once");

    // An optimistic challenge (no support message) is answered directly.
    let mut s = Spake::default();
    assert!(matches!(
        s.step(&ed, &challenge(1, &[1]), ikey()).unwrap(),
        Step::Respond
    ));
    assert!(s.respond(b"body").unwrap().is_some());

    // A challenge in a group we do not take: support, once; a second
    // such challenge fails.
    let mut s = Spake::default();
    assert!(matches!(
        s.step(&ed, &challenge(2, &[1]), ikey()).unwrap(),
        Step::Send(_)
    ));
    assert!(s.step(&ed, &challenge(2, &[1]), ikey()).is_err());
    // No SF-NONE among the factors: nothing we can answer.
    let mut s = Spake::default();
    assert!(s.step(&ed, &challenge(1, &[2]), ikey()).is_err());
}

/// Our edwards25519 scalar is a multiple of the cofactor, so a KDC (or
/// an attacker in its place) sending a point outside the prime-order
/// subgroup cannot steer the shared value into a small subgroup.
#[test]
fn edwards25519_private_scalars_clear_the_cofactor() {
    let w = [7u8; 32];
    for _ in 0..32 {
        let (private, _) = SpakeGroup::Edwards25519.keygen(&w, Mask::N).unwrap();
        assert_eq!(private[0] & 7, 0);
        assert!(private.iter().any(|&b| b != 0));
    }
    // A point of order 8 (from RFC 7748's list of small-order points)
    // makes K the identity, whatever w is.
    let order8 = hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05");
    let order8: [u8; 32] = order8.try_into().unwrap();
    let p = ed25519::Point::decode(&order8).unwrap();
    let (private, _) = SpakeGroup::Edwards25519.keygen(&w, Mask::N).unwrap();
    let theirs = p.add(&ed25519_mask(&w, Mask::M)).encode();
    let k = SpakeGroup::Edwards25519
        .result(&w, &private, &theirs, Mask::M)
        .unwrap();
    assert_eq!(k, ed25519::Point::IDENTITY.encode());
}

/// As MIT's `EC_POINT_oct2point` with the group's element length: only
/// a compressed point is the KDC's value.
#[cfg(feature = "spake-nist")]
#[test]
fn nist_values_must_be_compressed_points() {
    use p256::elliptic_curve::sec1::ToSec1Point;
    let g = SpakeGroup::P256;
    let w = [7u8; 32];
    let (private, public) = g.keygen(&w, Mask::M).unwrap();
    assert!(g.result(&w, &private, &public, Mask::M).is_ok());
    let point = p256::PublicKey::from_sec1_bytes(&public).unwrap();
    let uncompressed = point.to_sec1_point(false).as_bytes().to_vec();
    assert!(g.result(&w, &private, &uncompressed, Mask::M).is_err());
}

#[test]
fn group_lists_parse_as_mit_parses_them() {
    use SpakeGroup::*;
    let nist = cfg!(feature = "spake-nist");
    let want: Vec<SpakeGroup> = if nist {
        vec![P256, Edwards25519, P521]
    } else {
        vec![Edwards25519]
    };
    assert_eq!(
        SpakeGroup::parse_list("p-256, EDWARDS25519 bogus\tP-521 p-256"),
        want
    );
    assert_eq!(SpakeGroup::parse_list(""), []);
    assert_eq!(SpakeGroup::from_id(3), Some(P384));
}

/// Not a test: `cargo test --release --features spake-nist -- --ignored
/// spake_cost --nocapture` prints what one response costs per group.
#[test]
#[ignore]
fn spake_cost() {
    for g in SpakeGroup::ALL.into_iter().filter(|g| g.is_available()) {
        let ikey = Key::random(18).unwrap();
        let w = wbytes(g, &ikey).unwrap();
        let (_, t) = g.keygen(&w, Mask::M).unwrap();
        let n = 50;
        let start = std::time::Instant::now();
        for _ in 0..n {
            let (private, _) = g.keygen(&w, Mask::N).unwrap();
            g.result(&w, &private, &t, Mask::M).unwrap();
        }
        eprintln!("{}: {:?} a response", g.name(), start.elapsed() / n);
    }
}
