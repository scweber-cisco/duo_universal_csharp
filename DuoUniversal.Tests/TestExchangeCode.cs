// SPDX-FileCopyrightText: 2022 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using NUnit.Framework;

namespace DuoUniversal.Tests
{
    [TestFixture]
    public class TestExchangeCode : ClientTestBase
    {
        private const string CODE = "code";
        private const string NONCE = "a nonce of a plausible length";

        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public async Task TestSuccess()
        {
            string goodResponse = GoodApiResponse();
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(goodResponse)));
            IdToken idToken = await client.ExchangeAuthorizationCodeFor2faResult(CODE, USERNAME);
            Assert.AreEqual(idToken.Username, USERNAME);
        }

        [Test]
        public async Task TestSamlResponseSuccess()
        {
            string goodResponse = GoodApiResponseWithSamlResponse();
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(goodResponse)));
            string samlResponse = await client.ExchangeAuthorizationCodeForSamlResponse(CODE, USERNAME);
            Assert.NotNull(samlResponse);
        }

        [Test]
        [TestCase(HttpStatusCode.MovedPermanently)] // 301
        [TestCase(HttpStatusCode.BadRequest)] // 400
        [TestCase(HttpStatusCode.NotFound)] // 404
        [TestCase(HttpStatusCode.InternalServerError)] // 500
        public void TestBadHttpStatus(HttpStatusCode statusCode)
        {
            var client = MakeClient(new HttpResponder(statusCode, new StringContent("irrelevant")));
            Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeFor2faResult(CODE, USERNAME));
        }

        [Test]
        public void TestHttpException()
        {
            var client = MakeClient(new HttpExcepter());
            Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeFor2faResult(CODE, USERNAME));
        }

        [Test]
        [TestCase("Not username")]
        [TestCase("username@domain.org")]
        [TestCase("  username  ")]
        [TestCase("!@#user$%^name*&(")]
        public void TestUsernameMismatch(string username)
        {
            // Will have the USERNAME specified in the parent class
            string goodResponse = GoodApiResponse();
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(goodResponse)));
            Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeFor2faResult(CODE, username));
        }

        [Test]
        [TestCase("not username")]
        public void TestUsernameMismatchSamlResponseFailure(string username)
        {
            string goodResponse = GoodApiResponseWithSamlResponse();
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(goodResponse)));
            Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeForSamlResponse(CODE, username));
        }

        [Test]
        public async Task TestNonceSuccess()
        {
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponse(NONCE))));
            IdToken idToken = await client.ExchangeAuthorizationCodeFor2faResult(CODE, USERNAME, NONCE);
            Assert.AreEqual(NONCE, idToken.Nonce);
        }

        [Test]
        [TestCase("not the nonce")]
        [TestCase("")]
        [TestCase(null)]
        public void TestNonceMismatch(string expectedNonce)
        {
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponse(NONCE))));
            Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeFor2faResult(CODE, USERNAME, expectedNonce));
        }

        [Test]
        public void TestNonceMissingFromIdToken()
        {
            // Duo did not echo a nonce back, but we asked for one
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponse())));
            Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeFor2faResult(CODE, USERNAME, NONCE));
        }

        [Test]
        public async Task TestUnexpectedNonceIsIgnoredWhenNoneRequested()
        {
            // The two-argument overload does not request a nonce, so it does not check one
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponse(NONCE))));
            IdToken idToken = await client.ExchangeAuthorizationCodeFor2faResult(CODE, USERNAME);
            Assert.AreEqual(USERNAME, idToken.Username);
        }

        [Test]
        public async Task TestSamlResponseNonceSuccess()
        {
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponseWithSamlResponse(NONCE))));
            string samlResponse = await client.ExchangeAuthorizationCodeForSamlResponse(CODE, USERNAME, NONCE);
            Assert.NotNull(samlResponse);
        }

        [Test]
        public void TestSamlResponseNonceMismatch()
        {
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponseWithSamlResponse(NONCE))));
            Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeForSamlResponse(CODE, USERNAME, "not the nonce"));
        }

        private static string GoodApiResponse(string nonce = null)
        {
            var responseValues = new Dictionary<string, string>
            {
                {"access_token", "access token"},
                {"expires_in", "1"},
                {"id_token", CreateTokenJwt(nonce: nonce)},
                {"token_type", "Bearer"}
            };
            return JsonSerializer.Serialize(responseValues);
        }

        private static string GoodApiResponseWithSamlResponse(string nonce = null)
        {
            var responseValues = new Dictionary<string, string>
            {
                {"access_token", "access token"},
                {"expires_in", "1"},
                {"id_token", CreateTokenJwt(nonce: nonce)},
                {"token_type", "Bearer"},
                {"saml_response", "saml_response"}
            };
            return JsonSerializer.Serialize(responseValues);
        }
    }
}
