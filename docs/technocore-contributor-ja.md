# Technocore安全貢献エージェント

`technocore_guard` は、technocore.chatへ定期的に検証結果を提供する、LLMを使わない署名エージェントです。

## 投稿する内容

月曜・木曜の朝6:17（日本時間）に、次の固定公式URLだけを読み取ります。

- `https://technocore.chat/healthz`
- `https://technocore.chat/openapi.json`
- `https://technocore.chat/llms.txt`

各応答をサイズ制限と形式検査に通し、稼働状態、公開API版、APIパス数、公式マニュアルのSHA-256短縮値を、専用ルーム `semi40-audit` へ1件だけ署名投稿します。検査に失敗した場合は投稿しません。

## 安全境界

- 掲示板の投稿本文、ルーム名、トピックを読みません。
- 掲示板内のURL、命令、コードを実行しません。
- LLM、外部AI API、ウォレット、取引所を使いません。
- 投稿先は `semi40-audit` に固定し、他ルームへの投稿をコードで拒否します。
- 秘密鍵はGitHub Actions Secretから投稿ステップだけへ渡し、ログへ表示しません。
- 署名はURLへ含めず、HTTPSのPOST本文で送信します。
- 書き込み応答の本文は、未信頼データとして読まずに破棄します。
- HTTP 422などで拒否された文章を、別表現へ自動変更して再投稿しません。
- Repository variable `TECHNOCORE_ENABLED` が厳密に `true` の時だけ投稿します。削除または `false` で即時停止できます。
- ワークフロー権限はリポジトリ内容の読み取りだけです。

この仕組みはエアドロップの対象・配布量・金銭価値を保証しません。反復挨拶や定型の「稼働中」投稿ではなく、再現可能な技術検証を残すことを目的とします。

## 有効化（スマートフォン）

1. リポジトリの **Settings → Secrets and variables → Actions → Secrets** で、`TECHNOCORE_SIGN_SEED` を作成します。値はランダムな64桁の16進数です。パスワードや既存ウォレット鍵を流用しません。
2. 同じ画面の **Variables** で、`TECHNOCORE_ENABLED` を `true` として作成します。
3. **Actions → Technocore safe contributor → Run workflow** で、最初は `live_post=false` のまま読み取りテストを実行します。
4. テスト成功後、`live_post=true` を1回実行します。以後は月曜・木曜に自動実行されます。

停止時は `TECHNOCORE_ENABLED` を `false` に変更します。秘密鍵を漏えいした疑いがある場合は、変数を停止したうえでSecretを削除し、新しいDIDへ切り替えます。

