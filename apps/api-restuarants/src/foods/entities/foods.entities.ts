import { Field, ObjectType } from "@nestjs/graphql";

@ObjectType()
export class Images {
  @Field()
  public_id: string;

  @Field()
  url: string;
}

@ObjectType()
export class Food {
  @Field()
  id?: string;
  @Field()
  name: string;
  @Field({ nullable: true }) // Thay đổi đây để cho phép giá trị null
  phone?: string;

  @Field({ nullable: true }) // Thay đổi đây để cho phép giá trị null
  address?: string;
  @Field()
  description: string;

  @Field()
  price: number;

  @Field()
  estimatedPrice: number;

  @Field()
  category: string;

  @Field(() => [Images])
  images: Images[];

  @Field()
  restaurantId: string;

  @Field()
  createdAt?: Date;

  @Field()
  updatedAt?: Date;
}
